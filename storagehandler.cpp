#include "storagehandler.hpp"

#include "fruread.hpp"
#include "read_fru_data.hpp"
#include "selutility.hpp"
#include "sensorhandler.hpp"
#include "storageaddsel.hpp"
#include "utils.hpp"

#include <arpa/inet.h>
#include <host-ipmid/ipmid-api.h>
#include <mapper.h>
#include <systemd/sd-bus.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/server.hpp>
#include <sdrutils.hpp>
#include <string>
#include <xyz/openbmc_project/Common/error.hpp>

#if __has_include(<filesystem>)
#include <filesystem>
#elif __has_include(<experimental/filesystem>)
#include <experimental/filesystem>
#include <experimental/string_view>
namespace std
{
// splice experimental::filesystem into std
namespace filesystem = std::experimental::filesystem;
} // namespace std
#else
#error filesystem not available
#endif

void register_netfn_storage_functions() __attribute__((constructor));

unsigned int g_sel_time = 0xFFFFFFFF;
extern const ipmi::sensor::IdInfoMap sensors;
extern const FruMap frus;

namespace
{
constexpr auto TIME_INTERFACE = "xyz.openbmc_project.Time.EpochTime";
constexpr auto HOST_TIME_PATH = "/xyz/openbmc_project/time/host";
constexpr auto DBUS_PROPERTIES = "org.freedesktop.DBus.Properties";
constexpr auto PROPERTY_ELAPSED = "Elapsed";

const char* getTimeString(const uint64_t& usecSinceEpoch)
{
    using namespace std::chrono;
    system_clock::time_point tp{microseconds(usecSinceEpoch)};
    auto t = system_clock::to_time_t(tp);
    return std::ctime(&t);
}
} // namespace

using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
using namespace phosphor::logging;
using namespace ipmi::fru;

/**
 * @enum Device access mode
 */
enum class AccessMode
{
    bytes, ///< Device is accessed by bytes
    words  ///< Device is accessed by words
};

ipmi_ret_t ipmi_storage_wildcard(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                 ipmi_request_t request,
                                 ipmi_response_t response,
                                 ipmi_data_len_t data_len,
                                 ipmi_context_t context)
{
    // Status code.
    ipmi_ret_t rc = IPMI_CC_INVALID;
    *data_len = 0;
    return rc;
}

ipmi_ret_t getSELInfo(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                      ipmi_request_t request, ipmi_response_t response,
                      ipmi_data_len_t data_len, ipmi_context_t context)
{
    if (*data_len != 0)
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    ipmi::sel::GetSELInfoResponse* responseData =
        reinterpret_cast<ipmi::sel::GetSELInfoResponse*>(response);

    responseData->selVersion = ipmi::sel::selVersion;
    // Last erase timestamp is not available from log manager.
    responseData->eraseTimeStamp = ipmi::sel::invalidTimeStamp;
    responseData->operationSupport = ipmi::sel::selOperationSupport;

    responseData->entries = 0;
    int ret;
    sd_journal* journal;
    ret = sd_journal_open(&journal, SD_JOURNAL_LOCAL_ONLY);
    if (ret < 0)
    {
        log<level::ERR>("Failed to open journal: ",
                        entry("ERRNO=%s", strerror(-ret)));
    }
    else
    {
        char match[256];
        snprintf(match, sizeof(match), "MESSAGE_ID=%s",
                 ipmi::sel::selMessageId);
        sd_journal_add_match(journal, match, 0);
        SD_JOURNAL_FOREACH(journal)
        {
            responseData->entries++;
        }
        responseData->addTimeStamp = ipmi::sel::invalidTimeStamp;
        if ((ret = sd_journal_seek_tail(journal)) < 0)
        {
            log<level::ERR>("Failed to find seek_tail: ",
                            entry("ERRNO=%s", strerror(-ret)));
        }
        else
        {
            if ((ret = sd_journal_previous(journal)) <= 0)
            {
                log<level::ERR>("Failed to find a log entry: ",
                                entry("ERRNO=%s", strerror(-ret)));
            }
            else
            {
                uint64_t timestamp;
                if ((ret = sd_journal_get_realtime_usec(journal, &timestamp)) <
                    0)
                {
                    log<level::ERR>("Failed to read timestamp: ",
                                    entry("ERRNO=%s", strerror(-ret)));
                }
                else
                {
                    timestamp /= (1000 * 1000); // convert from us to s
                    responseData->addTimeStamp =
                        static_cast<uint32_t>(timestamp);
                }
            }
        }
        sd_journal_close(journal);
    }

    *data_len = sizeof(ipmi::sel::GetSELInfoResponse);

    return IPMI_CC_OK;
}

static void fromHexStr(const std::experimental::string_view hexStr,
                       std::vector<uint8_t>& data)
{
    for (unsigned int i = 0; i < hexStr.size(); i += 2)
    {
        std::string s = hexStr.substr(i, 2).to_string();
        data.push_back(static_cast<uint8_t>(std::stoul(s, nullptr, 16)));
    }
}

static int getJournalMetadata(sd_journal* journal,
                              const std::experimental::string_view& field,
                              std::experimental::string_view& contents)
{
    const char* data = nullptr;
    size_t length = 0;
    int ret = 0;
    // Get the metadata from the requested field of the journal entry
    ret = sd_journal_get_data(journal, field.data(), (const void**)&data,
                              &length);
    if (ret < 0)
    {
        return ret;
    }
    contents = std::experimental::string_view(data, length);
    // Only use the content after the "=" character.
    contents.remove_prefix(std::min(contents.find("=") + 1, contents.size()));
    return ret;
}

template <typename T>
static int getJournalMetadata(sd_journal* journal,
                              const std::experimental::string_view& field,
                              const int& base, T& contents)
{
    int ret = 0;
    std::experimental::string_view metadata;
    // Get the metadata from the requested field of the journal entry
    ret = getJournalMetadata(journal, field, metadata);
    if (ret < 0)
    {
        return ret;
    }
    contents = static_cast<T>(strtol(metadata.data(), nullptr, base));
    return ret;
}

static int getJournalSelData(sd_journal* journal, std::vector<uint8_t>& evtData)
{
    int ret = 0;
    std::experimental::string_view evtDataStr;
    // Get the OEM data from the IPMI_SEL_DATA field
    ret = getJournalMetadata(journal, "IPMI_SEL_DATA", evtDataStr);
    if (ret < 0)
    {
        return ret;
    }
    fromHexStr(evtDataStr, evtData);
    return ret;
}

ipmi_ret_t getSELEntry(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                       ipmi_request_t request, ipmi_response_t response,
                       ipmi_data_len_t data_len, ipmi_context_t context)
{
    if (*data_len != sizeof(ipmi::sel::GetSELEntryRequest))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    *data_len = 0; // Default to 0 in case of errors
    auto requestData =
        reinterpret_cast<const ipmi::sel::GetSELEntryRequest*>(request);

    if (requestData->reservationID != 0)
    {
        if (!checkSELReservation(requestData->reservationID))
        {
            return IPMI_CC_INVALID_RESERVATION_ID;
        }
    }

    ipmi::sel::GetSELEntryResponse record{};
    // Default as the last entry
    record.nextRecordID = ipmi::sel::lastEntry;

    // Check for the requested SEL Entry.
    int ret;
    sd_journal* journal;
    ret = sd_journal_open(&journal, SD_JOURNAL_LOCAL_ONLY);
    if (ret < 0)
    {
        log<level::ERR>("Failed to open journal: ",
                        entry("ERRNO=%s", strerror(-ret)));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    char match1[256];
    snprintf(match1, sizeof(match1), "MESSAGE_ID=%s", ipmi::sel::selMessageId);
    sd_journal_add_match(journal, match1, 0);

    // Get the requested target SEL record ID if first or last is requested.
    uint16_t targetID = requestData->selRecordID;
    if (targetID == ipmi::sel::firstEntry)
    {
        SD_JOURNAL_FOREACH(journal)
        {
            // Get the record ID from the IPMI_SEL_RECORD_ID field of the first
            // entry
            ret =
                getJournalMetadata(journal, "IPMI_SEL_RECORD_ID", 10, targetID);
            if (ret < 0)
            {
                sd_journal_close(journal);
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
            break;
        }
    }
    else if (targetID == ipmi::sel::lastEntry)
    {
        SD_JOURNAL_FOREACH_BACKWARDS(journal)
        {
            // Get the record ID from the IPMI_SEL_RECORD_ID field of the first
            // entry
            ret =
                getJournalMetadata(journal, "IPMI_SEL_RECORD_ID", 10, targetID);
            if (ret < 0)
            {
                sd_journal_close(journal);
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
            break;
        }
    }
    char match2[256];
    snprintf(match2, sizeof(match2), "IPMI_SEL_RECORD_ID=%d", targetID);
    sd_journal_add_match(journal, match2, 0);
    char match3[256];
    snprintf(match3, sizeof(match3), "IPMI_SEL_RECORD_ID=%d", targetID + 1);
    sd_journal_add_match(journal, match3, 0);
    SD_JOURNAL_FOREACH(journal)
    {
        // Get the record ID from the IPMI_SEL_RECORD_ID field
        uint16_t id;
        ret = getJournalMetadata(journal, "IPMI_SEL_RECORD_ID", 10, id);
        if (ret < 0)
        {
            sd_journal_close(journal);
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
        if (id == targetID)
        {
            // Found the desired record, so fill in the data
            record.recordID = id;

            // Get the record type from the IPMI_SEL_RECORD_TYPE field
            ret = getJournalMetadata(journal, "IPMI_SEL_RECORD_TYPE", 16,
                                     record.recordType);
            if (ret < 0)
            {
                sd_journal_close(journal);
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
            // The rest of the record depends on the record type
            if (record.recordType == ipmi::sel::systemEvent)
            {
                // Get the timestamp
                uint64_t ts = 0;
                ret = sd_journal_get_realtime_usec(journal, &ts);
                if (ret < 0)
                {
                    sd_journal_close(journal);
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
                record.timeStamp = static_cast<uint32_t>(
                    ts / 1000 / 1000); // Convert from us to s

                uint16_t generatorID;
                // Get the generator ID from the IPMI_SEL_GENERATOR_ID field
                ret = getJournalMetadata(journal, "IPMI_SEL_GENERATOR_ID", 16,
                                         generatorID);
                if (ret < 0)
                {
                    sd_journal_close(journal);
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
                record.generatorID = generatorID;
                // Set the event message revision
                record.eventMsgRevision = ipmi::sel::eventMsgRev;

                std::experimental::string_view path;
                // Get the IPMI_SEL_SENSOR_PATH field
                ret = getJournalMetadata(journal, "IPMI_SEL_SENSOR_PATH", path);
                if (ret < 0)
                {
                    sd_journal_close(journal);
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
                record.sensorType = getSensorTypeFromPath(path.to_string());
                record.sensorNum = getSensorNumberFromPath(path.to_string());
                record.eventType = getSensorEventTypeFromPath(path.to_string());

                uint8_t eventDir;
                // Get the event direction from the IPMI_SEL_EVENT_DIR field
                ret = getJournalMetadata(journal, "IPMI_SEL_EVENT_DIR", 16,
                                         eventDir);
                if (ret < 0)
                {
                    sd_journal_close(journal);
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
                // Set the event direction
                if (eventDir == 0)
                {
                    record.eventType |= 0x80;
                }

                std::vector<uint8_t> evtData;
                // Get the event data from the IPMI_SEL_DATA field
                ret = getJournalSelData(journal, evtData);
                if (ret < 0)
                {
                    sd_journal_close(journal);
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
                record.eventData1 = evtData[0];
                record.eventData2 = evtData[1];
                record.eventData3 = evtData[2];
            }
            else if (record.recordType >= ipmi::sel::oemTsEventFirst &&
                     record.recordType <= ipmi::sel::oemTsEventLast)
            {
                // Get the timestamp
                uint64_t timestamp = 0;
                ret = sd_journal_get_realtime_usec(journal, &timestamp);
                if (ret < 0)
                {
                    sd_journal_close(journal);
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
                record.timeStamp = static_cast<uint32_t>(
                    timestamp / 1000 / 1000); // Convert from us to s

                std::vector<uint8_t> evtData;
                // Get the OEM data from the IPMI_SEL_DATA field
                ret = getJournalSelData(journal, evtData);
                if (ret < 0)
                {
                    sd_journal_close(journal);
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
                // Only keep the bytes that fit in the record
                std::copy_n(evtData.begin(),
                            std::min(evtData.size(), ipmi::sel::oemTsEventSize),
                            reinterpret_cast<uint8_t*>(&(record.generatorID)));
            }
            else if (record.recordType >= ipmi::sel::oemEventFirst &&
                     record.recordType <= ipmi::sel::oemEventLast)
            {
                std::vector<uint8_t> evtData;
                // Get the OEM data from the IPMI_SEL_DATA field
                ret = getJournalSelData(journal, evtData);
                if (ret < 0)
                {
                    sd_journal_close(journal);
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
                // Only keep the bytes that fit in the record
                std::copy_n(evtData.begin(),
                            std::min(evtData.size(), ipmi::sel::oemEventSize),
                            reinterpret_cast<uint8_t*>(&(record.timeStamp)));
            }
        }
        else if (id == targetID + 1)
        {
            record.nextRecordID = id;
        }
    }
    sd_journal_close(journal);

    // If we didn't find the requested record, return an error
    if (record.recordID == 0)
    {
        return IPMI_CC_SENSOR_INVALID;
    }

    if (requestData->readLength == ipmi::sel::entireRecord)
    {
        std::copy(&record, &record + 1,
                  static_cast<ipmi::sel::GetSELEntryResponse*>(response));
        *data_len = sizeof(record);
    }
    else
    {
        if (requestData->reservationID == 0)
        {
            return IPMI_CC_INVALID_RESERVATION_ID;
        }
        if (requestData->offset >= ipmi::sel::selRecordSize ||
            requestData->readLength > ipmi::sel::selRecordSize)
        {
            return IPMI_CC_INVALID_FIELD_REQUEST;
        }

        auto diff = ipmi::sel::selRecordSize - requestData->offset;
        auto readLength =
            std::min(diff, static_cast<int>(requestData->readLength));

        *static_cast<uint16_t*>(response) = record.nextRecordID;
        std::copy(
            reinterpret_cast<uint8_t*>(&record.recordID) + requestData->offset,
            reinterpret_cast<uint8_t*>(&record.recordID) + requestData->offset +
                readLength,
            static_cast<uint8_t*>(response) + sizeof(record.nextRecordID));
        *data_len = sizeof(record.nextRecordID) + readLength;
    }

    return IPMI_CC_OK;
}

ipmi_ret_t clearSEL(ipmi_netfn_t netfn, ipmi_cmd_t cmd, ipmi_request_t request,
                    ipmi_response_t response, ipmi_data_len_t data_len,
                    ipmi_context_t context)
{
    if (*data_len != sizeof(ipmi::sel::ClearSELRequest))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    auto requestData =
        reinterpret_cast<const ipmi::sel::ClearSELRequest*>(request);

    if (!checkSELReservation(requestData->reservationID))
    {
        *data_len = 0;
        return IPMI_CC_INVALID_RESERVATION_ID;
    }

    if (requestData->charC != 'C' || requestData->charL != 'L' ||
        requestData->charR != 'R')
    {
        *data_len = 0;
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    uint8_t eraseProgress = ipmi::sel::eraseComplete;

    /*
     * Erasure status cannot be fetched from DBUS, so always return erasure
     * status as `erase completed`.
     */
    if (requestData->eraseOperation == ipmi::sel::getEraseStatus)
    {
        *static_cast<uint8_t*>(response) = eraseProgress;
        *data_len = sizeof(eraseProgress);
        return IPMI_CC_OK;
    }

    // Per the IPMI spec, need to cancel any reservation when the SEL is cleared
    cancelSELReservation();

    // Clear the SEL by by rotating the journal to start a new file then
    // vacuuming to keep only the new file
    if (system("journalctl --rotate") != 0)
    {
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    if (system("journalctl --vacuum-files=1") != 0)
    {
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    *static_cast<uint8_t*>(response) = eraseProgress;
    *data_len = sizeof(eraseProgress);
    return IPMI_CC_OK;
}

ipmi_ret_t ipmi_storage_get_sel_time(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                     ipmi_request_t request,
                                     ipmi_response_t response,
                                     ipmi_data_len_t data_len,
                                     ipmi_context_t context)
{
    using namespace std::chrono;
    uint64_t host_time_usec = 0;
    uint32_t resp = 0;
    std::stringstream hostTime;

    try
    {
        sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
        auto service = ipmi::getService(bus, TIME_INTERFACE, HOST_TIME_PATH);
        sdbusplus::message::variant<uint64_t> value;

        // Get host time
        auto method = bus.new_method_call(service.c_str(), HOST_TIME_PATH,
                                          DBUS_PROPERTIES, "Get");

        method.append(TIME_INTERFACE, PROPERTY_ELAPSED);
        auto reply = bus.call(method);
        if (reply.is_method_error())
        {
            log<level::ERR>("Error getting time",
                            entry("SERVICE=%s", service.c_str()),
                            entry("PATH=%s", HOST_TIME_PATH));
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
        reply.read(value);
        host_time_usec = value.get<uint64_t>();
    }
    catch (InternalFailure& e)
    {
        log<level::ERR>(e.what());
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    catch (const std::runtime_error& e)
    {
        log<level::ERR>(e.what());
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    hostTime << "Host time:" << getTimeString(host_time_usec);
    log<level::DEBUG>(hostTime.str().c_str());

    // Time is really long int but IPMI wants just uint32. This works okay until
    // the number of seconds since 1970 overflows uint32 size.. Still a whole
    // lot of time here to even think about that.
    resp = duration_cast<seconds>(microseconds(host_time_usec)).count();
    resp = htole32(resp);

    // From the IPMI Spec 2.0, response should be a 32-bit value
    *data_len = sizeof(resp);

    // Pack the actual response
    std::memcpy(response, &resp, *data_len);

    return IPMI_CC_OK;
}

ipmi_ret_t ipmi_storage_set_sel_time(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                     ipmi_request_t request,
                                     ipmi_response_t response,
                                     ipmi_data_len_t data_len,
                                     ipmi_context_t context)
{
    using namespace std::chrono;
    ipmi_ret_t rc = IPMI_CC_OK;
    uint32_t secs = *static_cast<uint32_t*>(request);
    *data_len = 0;

    secs = le32toh(secs);
    microseconds usec{seconds(secs)};

    try
    {
        sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
        auto service = ipmi::getService(bus, TIME_INTERFACE, HOST_TIME_PATH);
        sdbusplus::message::variant<uint64_t> value{usec.count()};

        // Set host time
        auto method = bus.new_method_call(service.c_str(), HOST_TIME_PATH,
                                          DBUS_PROPERTIES, "Set");

        method.append(TIME_INTERFACE, PROPERTY_ELAPSED, value);
        auto reply = bus.call(method);
        if (reply.is_method_error())
        {
            log<level::ERR>("Error setting time",
                            entry("SERVICE=%s", service.c_str()),
                            entry("PATH=%s", HOST_TIME_PATH));
            rc = IPMI_CC_UNSPECIFIED_ERROR;
        }
    }
    catch (InternalFailure& e)
    {
        log<level::ERR>(e.what());
        rc = IPMI_CC_UNSPECIFIED_ERROR;
    }
    catch (const std::runtime_error& e)
    {
        log<level::ERR>(e.what());
        rc = IPMI_CC_UNSPECIFIED_ERROR;
    }

    return rc;
}

ipmi_ret_t ipmi_storage_reserve_sel(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                    ipmi_request_t request,
                                    ipmi_response_t response,
                                    ipmi_data_len_t data_len,
                                    ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    unsigned short selResID = reserveSel();

    *data_len = sizeof(selResID);

    // Pack the actual response
    std::memcpy(response, &selResID, *data_len);

    return rc;
}

ipmi_ret_t addSELEntry(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                       ipmi_request_t request, ipmi_response_t response,
                       ipmi_data_len_t data_len, ipmi_context_t context)
{
    static constexpr char const* ipmiSELObject =
        "xyz.openbmc_project.Logging.IPMI";
    static constexpr char const* ipmiSELPath =
        "/xyz/openbmc_project/Logging/IPMI";
    static constexpr char const* ipmiSELAddInterface =
        "xyz.openbmc_project.Logging.IPMI";
    static const std::string ipmiSELAddMessage =
        "IPMI SEL entry logged using IPMI Add SEL Entry command.";
    uint16_t recordID = 0;
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};

    if (*data_len != sizeof(ipmi_add_sel_request_t))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    ipmi_add_sel_request_t* req = (ipmi_add_sel_request_t*)request;

    // Per the IPMI spec, need to cancel any reservation when a SEL entry is
    // added
    cancelSELReservation();

    if (req->recordtype == ipmi::sel::systemEvent)
    {
        std::string sensorPath = getPathFromSensorNumber(req->sensornumber);
        std::vector<uint8_t> eventData(
            req->eventdata, req->eventdata + ipmi::sel::systemEventSize);
        bool assert = req->eventdir & 0x80 ? false : true;
        uint16_t genId = req->generatorid[0] |
                         static_cast<uint16_t>(req->generatorid[1]) << 8;
        sdbusplus::message::message writeSEL = bus.new_method_call(
            ipmiSELObject, ipmiSELPath, ipmiSELAddInterface, "IpmiSelAdd");
        writeSEL.append(ipmiSELAddMessage, sensorPath, eventData, assert,
                        genId);
        try
        {
            sdbusplus::message::message writeSELResp = bus.call(writeSEL);
            writeSELResp.read(recordID);
        }
        catch (sdbusplus::exception_t&)
        {
            log<level::ERR>("error writing SEL");
            *data_len = 0;
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
    }
    else if (req->recordtype >= ipmi::sel::oemTsEventFirst &&
             req->recordtype <= ipmi::sel::oemTsEventLast)
    {
        std::vector<uint8_t> eventData(
            req->generatorid, req->generatorid + ipmi::sel::oemTsEventSize);
        sdbusplus::message::message writeSEL = bus.new_method_call(
            ipmiSELObject, ipmiSELPath, ipmiSELAddInterface, "IpmiSelAddOem");
        writeSEL.append(ipmiSELAddMessage, eventData, req->recordtype);
        try
        {
            sdbusplus::message::message writeSELResp = bus.call(writeSEL);
            writeSELResp.read(recordID);
        }
        catch (sdbusplus::exception_t&)
        {
            log<level::ERR>("error writing SEL");
            *data_len = 0;
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
    }
    else if (req->recordtype >= ipmi::sel::oemEventFirst &&
             req->recordtype <= ipmi::sel::oemEventLast)
    {
        std::vector<uint8_t> eventData(
            req->timestamp, req->timestamp + ipmi::sel::oemEventSize);
        sdbusplus::message::message writeSEL = bus.new_method_call(
            ipmiSELObject, ipmiSELPath, ipmiSELAddInterface, "IpmiSelAddOem");
        writeSEL.append(ipmiSELAddMessage, eventData, req->recordtype);
        try
        {
            sdbusplus::message::message writeSELResp = bus.call(writeSEL);
            writeSELResp.read(recordID);
        }
        catch (sdbusplus::exception_t&)
        {
            log<level::ERR>("error writing SEL");
            *data_len = 0;
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
    }

    *static_cast<uint16_t*>(response) = recordID;
    *data_len = sizeof(recordID);
    return IPMI_CC_OK;
}

// Read FRU info area
ipmi_ret_t ipmi_storage_get_fru_inv_area_info(
    ipmi_netfn_t netfn, ipmi_cmd_t cmd, ipmi_request_t request,
    ipmi_response_t response, ipmi_data_len_t data_len, ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    const FruInvenAreaInfoRequest* reqptr =
        reinterpret_cast<const FruInvenAreaInfoRequest*>(request);

    auto iter = frus.find(reqptr->fruID);
    if (iter == frus.end())
    {
        *data_len = 0;
        return IPMI_CC_SENSOR_INVALID;
    }

    try
    {
        const auto& fruArea = getFruAreaData(reqptr->fruID);
        auto size = static_cast<uint16_t>(fruArea.size());
        FruInvenAreaInfoResponse resp;
        resp.sizems = size >> 8;
        resp.sizels = size;
        resp.access = static_cast<uint8_t>(AccessMode::bytes);

        *data_len = sizeof(resp);

        // Pack the actual response
        std::memcpy(response, &resp, *data_len);
    }
    catch (const InternalFailure& e)
    {
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        *data_len = 0;
        log<level::ERR>(e.what());
    }
    return rc;
}

// Read FRU data
ipmi_ret_t ipmi_storage_read_fru_data(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                      ipmi_request_t request,
                                      ipmi_response_t response,
                                      ipmi_data_len_t data_len,
                                      ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    const ReadFruDataRequest* reqptr =
        reinterpret_cast<const ReadFruDataRequest*>(request);
    auto resptr = reinterpret_cast<ReadFruDataResponse*>(response);

    auto iter = frus.find(reqptr->fruID);
    if (iter == frus.end())
    {
        *data_len = 0;
        return IPMI_CC_SENSOR_INVALID;
    }

    auto offset =
        static_cast<uint16_t>(reqptr->offsetMS << 8 | reqptr->offsetLS);
    try
    {
        const auto& fruArea = getFruAreaData(reqptr->fruID);
        auto size = fruArea.size();

        if (offset >= size)
        {
            return IPMI_CC_PARM_OUT_OF_RANGE;
        }

        // Write the count of response data.
        if ((offset + reqptr->count) <= size)
        {
            resptr->count = reqptr->count;
        }
        else
        {
            resptr->count = size - offset;
        }

        std::copy((fruArea.begin() + offset),
                  (fruArea.begin() + offset + resptr->count), resptr->data);

        *data_len = resptr->count + 1; // additional one byte for count
    }
    catch (const InternalFailure& e)
    {
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        *data_len = 0;
        log<level::ERR>(e.what());
    }
    return rc;
}

ipmi_ret_t ipmi_get_repository_info(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                    ipmi_request_t request,
                                    ipmi_response_t response,
                                    ipmi_data_len_t data_len,
                                    ipmi_context_t context)
{
    constexpr auto sdrVersion = 0x51;
    auto responseData = reinterpret_cast<GetRepositoryInfoResponse*>(response);

    std::memset(responseData, 0, sizeof(GetRepositoryInfoResponse));

    responseData->sdrVersion = sdrVersion;

    uint16_t records = frus.size() + sensors.size();
    responseData->recordCountMs = records >> 8;
    responseData->recordCountLs = records;

    responseData->freeSpace[0] = 0xFF;
    responseData->freeSpace[1] = 0xFF;

    *data_len = sizeof(GetRepositoryInfoResponse);

    return IPMI_CC_OK;
}

void register_netfn_storage_functions()
{
    // <Wildcard Command>
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_WILDCARD, NULL,
                           ipmi_storage_wildcard, PRIVILEGE_USER);

    // <Get SEL Info>
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_GET_SEL_INFO, NULL,
                           getSELInfo, PRIVILEGE_USER);

    // <Get SEL Time>
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_GET_SEL_TIME, NULL,
                           ipmi_storage_get_sel_time, PRIVILEGE_USER);

    // <Set SEL Time>
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_SET_SEL_TIME, NULL,
                           ipmi_storage_set_sel_time, PRIVILEGE_OPERATOR);

    // <Reserve SEL>
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_RESERVE_SEL, NULL,
                           ipmi_storage_reserve_sel, PRIVILEGE_USER);

    // <Get SEL Entry>
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_GET_SEL_ENTRY, NULL,
                           getSELEntry, PRIVILEGE_USER);

    // <Add SEL Entry>
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_ADD_SEL, NULL, addSELEntry,
                           PRIVILEGE_OPERATOR);
    // <Clear SEL>
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_CLEAR_SEL, NULL, clearSEL,
                           PRIVILEGE_OPERATOR);
    // <Get FRU Inventory Area Info>
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_GET_FRU_INV_AREA_INFO, NULL,
                           ipmi_storage_get_fru_inv_area_info,
                           PRIVILEGE_OPERATOR);

    // <Add READ FRU Data
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_READ_FRU_DATA, NULL,
                           ipmi_storage_read_fru_data, PRIVILEGE_OPERATOR);

    // <Get Repository Info>
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_GET_REPOSITORY_INFO,
                           nullptr, ipmi_get_repository_info, PRIVILEGE_USER);

    // <Reserve SDR Repository>
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_RESERVE_SDR, nullptr,
                           ipmi_sen_reserve_sdr, PRIVILEGE_USER);

    // <Get SDR>
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_GET_SDR, nullptr,
                           ipmi_sen_get_sdr, PRIVILEGE_USER);

    ipmi::fru::registerCallbackHandler();
    return;
}
