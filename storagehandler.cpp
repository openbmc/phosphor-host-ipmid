#include "storagehandler.hpp"

#include "fruread.hpp"
#include "read_fru_data.hpp"
#include "selutility.hpp"
#include "sensorhandler.hpp"
#include "storageaddsel.hpp"

#include <arpa/inet.h>
#include <ipmid/api.h>
#include <mapper.h>
#include <systemd/sd-bus.h>

#include <algorithm>
#include <boost/process.hpp>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <ipmid/utils.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/message/types.hpp>
#include <sdbusplus/server.hpp>
#include <sdrutils.hpp>
#include <string>
#include <string_view>
#include <xyz/openbmc_project/Common/error.hpp>

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

#ifndef JOURNAL_SEL
namespace cache
{
/*
 * This cache contains the object paths of the logging entries sorted in the
 * order of the filename(numeric order). The cache is initialized by
 * invoking readLoggingObjectPaths with the cache as the parameter. The
 * cache is invoked in the execution of the Get SEL info and Delete SEL
 * entry command. The Get SEL Info command is typically invoked before the
 * Get SEL entry command, so the cache is utilized for responding to Get SEL
 * entry command. The cache is invalidated by clearing after Delete SEL
 * entry and Clear SEL command.
 */
ipmi::sel::ObjectPaths paths;

} // namespace cache
#endif

namespace variant_ns = sdbusplus::message::variant_ns;

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

#ifdef JOURNAL_SEL
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
        static_cast<ipmi::sel::GetSELInfoResponse*>(response);

    responseData->selVersion = ipmi::sel::selVersion;
    // Last erase timestamp is not available from log manager.
    responseData->eraseTimeStamp = ipmi::sel::invalidTimeStamp;
    responseData->addTimeStamp = ipmi::sel::invalidTimeStamp;
    responseData->operationSupport = ipmi::sel::selOperationSupport;
    responseData->entries = 0;

    // Open the journal
    sd_journal* journalTmp = nullptr;
    if (int ret = sd_journal_open(&journalTmp, SD_JOURNAL_LOCAL_ONLY); ret < 0)
    {
        log<level::ERR>("Failed to open journal: ",
                        entry("ERRNO=%s", strerror(-ret)));
        return IPMI_CC_RESPONSE_ERROR;
    }
    std::unique_ptr<sd_journal, decltype(&sd_journal_close)> journal(
        journalTmp, sd_journal_close);
    journalTmp = nullptr;

    // Filter the journal based on the SEL MESSAGE_ID
    std::string match = "MESSAGE_ID=" + std::string(ipmi::sel::selMessageId);
    sd_journal_add_match(journal.get(), match.c_str(), 0);

    // Count the number of SEL Entries in the journal and get the timestamp of
    // the newest entry
    bool timestampRecorded = false;
    SD_JOURNAL_FOREACH_BACKWARDS(journal.get())
    {
        if (!timestampRecorded)
        {
            uint64_t timestamp;
            if (int ret =
                    sd_journal_get_realtime_usec(journal.get(), &timestamp);
                ret < 0)
            {
                log<level::ERR>("Failed to read timestamp: ",
                                entry("ERRNO=%s", strerror(-ret)));
                return IPMI_CC_RESPONSE_ERROR;
            }
            timestamp /= (1000 * 1000); // convert from us to s
            responseData->addTimeStamp = static_cast<uint32_t>(timestamp);
            timestampRecorded = true;
        }
        responseData->entries++;
    }

    *data_len = sizeof(ipmi::sel::GetSELInfoResponse);
    return IPMI_CC_OK;
}

static int fromHexStr(const std::string hexStr, std::vector<uint8_t>& data)
{
    for (unsigned int i = 0; i < hexStr.size(); i += 2)
    {
        try
        {
            data.push_back(static_cast<uint8_t>(
                std::stoul(hexStr.substr(i, 2), nullptr, 16)));
        }
        catch (std::invalid_argument& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
            return -1;
        }
        catch (std::out_of_range& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
            return -1;
        }
    }
    return 0;
}

static int getJournalMetadata(sd_journal* journal,
                              const std::string_view& field,
                              std::string& contents)
{
    const char* data = nullptr;
    size_t length = 0;

    // Get the metadata from the requested field of the journal entry
    if (int ret = sd_journal_get_data(journal, field.data(),
                                      (const void**)&data, &length);
        ret < 0)
    {
        return ret;
    }
    std::string_view metadata(data, length);
    // Only use the content after the "=" character.
    metadata.remove_prefix(std::min(metadata.find("=") + 1, metadata.size()));
    contents = std::string(metadata);
    return 0;
}

static int getJournalMetadata(sd_journal* journal,
                              const std::string_view& field, const int& base,
                              int& contents)
{
    std::string metadata;
    // Get the metadata from the requested field of the journal entry
    if (int ret = getJournalMetadata(journal, field, metadata); ret < 0)
    {
        return ret;
    }
    try
    {
        contents = static_cast<int>(std::stoul(metadata, nullptr, base));
    }
    catch (std::invalid_argument& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return -1;
    }
    catch (std::out_of_range& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return -1;
    }
    return 0;
}

static int getJournalSelData(sd_journal* journal, std::vector<uint8_t>& evtData)
{
    std::string evtDataStr;
    // Get the OEM data from the IPMI_SEL_DATA field
    if (int ret = getJournalMetadata(journal, "IPMI_SEL_DATA", evtDataStr);
        ret < 0)
    {
        return ret;
    }
    return fromHexStr(evtDataStr, evtData);
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
        static_cast<const ipmi::sel::GetSELEntryRequest*>(request);

    if (requestData->reservationID != 0 || requestData->offset != 0)
    {
        if (!checkSELReservation(requestData->reservationID))
        {
            return IPMI_CC_INVALID_RESERVATION_ID;
        }
    }

    // Check for the requested SEL Entry.
    sd_journal* journalTmp;
    if (int ret = sd_journal_open(&journalTmp, SD_JOURNAL_LOCAL_ONLY); ret < 0)
    {
        log<level::ERR>("Failed to open journal: ",
                        entry("ERRNO=%s", strerror(-ret)));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    std::unique_ptr<sd_journal, decltype(&sd_journal_close)> journal(
        journalTmp, sd_journal_close);
    journalTmp = nullptr;

    std::string match = "MESSAGE_ID=" + std::string(ipmi::sel::selMessageId);
    sd_journal_add_match(journal.get(), match.c_str(), 0);

    // Get the requested target SEL record ID if first or last is requested.
    int targetID = requestData->selRecordID;
    if (targetID == ipmi::sel::firstEntry)
    {
        SD_JOURNAL_FOREACH(journal.get())
        {
            // Get the record ID from the IPMI_SEL_RECORD_ID field of the first
            // entry
            if (getJournalMetadata(journal.get(), "IPMI_SEL_RECORD_ID", 10,
                                   targetID) < 0)
            {
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
            break;
        }
    }
    else if (targetID == ipmi::sel::lastEntry)
    {
        SD_JOURNAL_FOREACH_BACKWARDS(journal.get())
        {
            // Get the record ID from the IPMI_SEL_RECORD_ID field of the first
            // entry
            if (getJournalMetadata(journal.get(), "IPMI_SEL_RECORD_ID", 10,
                                   targetID) < 0)
            {
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
            break;
        }
    }
    // Find the requested ID
    match = "IPMI_SEL_RECORD_ID=" + std::to_string(targetID);
    sd_journal_add_match(journal.get(), match.c_str(), 0);
    // And find the next ID (wrapping to Record ID 1 when necessary)
    int nextID = targetID + 1;
    if (nextID == ipmi::sel::lastEntry)
    {
        nextID = 1;
    }
    match = "IPMI_SEL_RECORD_ID=" + std::to_string(nextID);
    sd_journal_add_match(journal.get(), match.c_str(), 0);
    SD_JOURNAL_FOREACH(journal.get())
    {
        // Get the record ID from the IPMI_SEL_RECORD_ID field
        int id = 0;
        if (getJournalMetadata(journal.get(), "IPMI_SEL_RECORD_ID", 10, id) < 0)
        {
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
        if (id == targetID)
        {
            // Found the desired record, so fill in the data
            int recordType = 0;
            // Get the record type from the IPMI_SEL_RECORD_TYPE field
            if (getJournalMetadata(journal.get(), "IPMI_SEL_RECORD_TYPE", 16,
                                   recordType) < 0)
            {
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
            // The record content depends on the record type
            if (recordType == ipmi::sel::systemEvent)
            {
                ipmi::sel::GetSELEntryResponse* record =
                    static_cast<ipmi::sel::GetSELEntryResponse*>(response);

                // Set the record ID
                record->recordID = id;

                // Set the record type
                record->recordType = recordType;

                // Get the timestamp
                uint64_t ts = 0;
                if (sd_journal_get_realtime_usec(journal.get(), &ts) < 0)
                {
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
                record->timeStamp = static_cast<uint32_t>(
                    ts / 1000 / 1000); // Convert from us to s

                int generatorID = 0;
                // Get the generator ID from the IPMI_SEL_GENERATOR_ID field
                if (getJournalMetadata(journal.get(), "IPMI_SEL_GENERATOR_ID",
                                       16, generatorID) < 0)
                {
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
                record->generatorID = generatorID;

                // Set the event message revision
                record->eventMsgRevision = ipmi::sel::eventMsgRev;

                std::string path;
                // Get the IPMI_SEL_SENSOR_PATH field
                if (getJournalMetadata(journal.get(), "IPMI_SEL_SENSOR_PATH",
                                       path) < 0)
                {
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
                record->sensorType = getSensorTypeFromPath(path);
                record->sensorNum = getSensorNumberFromPath(path);
                record->eventType = getSensorEventTypeFromPath(path);

                int eventDir = 0;
                // Get the event direction from the IPMI_SEL_EVENT_DIR field
                if (getJournalMetadata(journal.get(), "IPMI_SEL_EVENT_DIR", 16,
                                       eventDir) < 0)
                {
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
                // Set the event direction
                if (eventDir == 0)
                {
                    record->eventType |= ipmi::sel::deassertionEvent;
                }

                std::vector<uint8_t> evtData;
                // Get the event data from the IPMI_SEL_DATA field
                if (getJournalSelData(journal.get(), evtData) < 0)
                {
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
                record->eventData1 = evtData[0];
                record->eventData2 = evtData[1];
                record->eventData3 = evtData[2];
            }
            else if (recordType >= ipmi::sel::oemTsEventFirst &&
                     recordType <= ipmi::sel::oemTsEventLast)
            {
                ipmi::sel::GetSELEntryResponseOEMTimestamped* oemTsRecord =
                    static_cast<ipmi::sel::GetSELEntryResponseOEMTimestamped*>(
                        response);

                // Set the record ID
                oemTsRecord->recordID = id;

                // Set the record type
                oemTsRecord->recordType = recordType;

                // Get the timestamp
                uint64_t timestamp = 0;
                if (sd_journal_get_realtime_usec(journal.get(), &timestamp) < 0)
                {
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
                oemTsRecord->timestamp = static_cast<uint32_t>(
                    timestamp / 1000 / 1000); // Convert from us to s

                std::vector<uint8_t> evtData;
                // Get the OEM data from the IPMI_SEL_DATA field
                if (getJournalSelData(journal.get(), evtData) < 0)
                {
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
                // Only keep the bytes that fit in the record
                std::copy_n(evtData.begin(),
                            std::min(evtData.size(), ipmi::sel::oemTsEventSize),
                            oemTsRecord->eventData);
            }
            else if (recordType >= ipmi::sel::oemEventFirst &&
                     recordType <= ipmi::sel::oemEventLast)
            {
                ipmi::sel::GetSELEntryResponseOEM* oemRecord =
                    static_cast<ipmi::sel::GetSELEntryResponseOEM*>(response);

                // Set the record ID
                oemRecord->recordID = id;

                // Set the record type
                oemRecord->recordType = recordType;

                std::vector<uint8_t> evtData;
                // Get the OEM data from the IPMI_SEL_DATA field
                if (getJournalSelData(journal.get(), evtData) < 0)
                {
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
                // Only keep the bytes that fit in the record
                std::copy_n(evtData.begin(),
                            std::min(evtData.size(), ipmi::sel::oemEventSize),
                            oemRecord->eventData);
            }
        }
        else if (id == nextID)
        {
            ipmi::sel::GetSELEntryResponse* record =
                static_cast<ipmi::sel::GetSELEntryResponse*>(response);
            record->nextRecordID = id;
        }
    }

    ipmi::sel::GetSELEntryResponse* record =
        static_cast<ipmi::sel::GetSELEntryResponse*>(response);

    // If we didn't find the requested record, return an error
    if (record->recordID == 0)
    {
        return IPMI_CC_SENSOR_INVALID;
    }

    // If we didn't find the next record ID, then mark it as the last entry
    if (record->nextRecordID == 0)
    {
        record->nextRecordID = ipmi::sel::lastEntry;
    }

    *data_len = sizeof(ipmi::sel::GetSELEntryResponse);
    if (requestData->readLength != ipmi::sel::entireRecord)
    {
        if (requestData->offset + requestData->readLength >
            ipmi::sel::selRecordSize)
        {
            return IPMI_CC_PARM_OUT_OF_RANGE;
        }

        auto diff = ipmi::sel::selRecordSize - requestData->offset;
        auto readLength =
            std::min(diff, static_cast<int>(requestData->readLength));

        uint8_t* partialRecord = static_cast<uint8_t*>(response);
        std::copy_n(partialRecord + sizeof(record->nextRecordID) +
                        requestData->offset,
                    readLength, partialRecord + sizeof(record->nextRecordID));
        *data_len = sizeof(record->nextRecordID) + readLength;
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
    auto requestData = static_cast<const ipmi::sel::ClearSELRequest*>(request);

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
    if (boost::process::system("/bin/journalctl", "--rotate") != 0)
    {
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    if (boost::process::system("/bin/journalctl", "--vacuum-files=1") != 0)
    {
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    *static_cast<uint8_t*>(response) = eraseProgress;
    *data_len = sizeof(eraseProgress);
    return IPMI_CC_OK;
}
#else  // JOURNAL_SEL not used
ipmi_ret_t getSELInfo(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                      ipmi_request_t request, ipmi_response_t response,
                      ipmi_data_len_t data_len, ipmi_context_t context)
{
    if (*data_len != 0)
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    std::vector<uint8_t> outPayload(sizeof(ipmi::sel::GetSELInfoResponse));
    auto responseData =
        reinterpret_cast<ipmi::sel::GetSELInfoResponse*>(outPayload.data());

    responseData->selVersion = ipmi::sel::selVersion;
    // Last erase timestamp is not available from log manager.
    responseData->eraseTimeStamp = ipmi::sel::invalidTimeStamp;
    responseData->operationSupport = ipmi::sel::operationSupport;

    try
    {
        ipmi::sel::readLoggingObjectPaths(cache::paths);
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        // No action if reading log objects have failed for this command.
        // readLoggingObjectPaths will throw exception if there are no log
        // entries. The command will be responded with number of SEL entries
        // as 0.
    }

    responseData->entries = 0;
    responseData->addTimeStamp = ipmi::sel::invalidTimeStamp;

    if (!cache::paths.empty())
    {
        responseData->entries = static_cast<uint16_t>(cache::paths.size());

        try
        {
            responseData->addTimeStamp = static_cast<uint32_t>(
                (ipmi::sel::getEntryTimeStamp(cache::paths.back()).count()));
        }
        catch (InternalFailure& e)
        {
        }
        catch (const std::runtime_error& e)
        {
            log<level::ERR>(e.what());
        }
    }

    std::memcpy(response, outPayload.data(), outPayload.size());
    *data_len = outPayload.size();

    return IPMI_CC_OK;
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

    auto requestData =
        reinterpret_cast<const ipmi::sel::GetSELEntryRequest*>(request);

    if (requestData->reservationID != 0)
    {
        if (!checkSELReservation(requestData->reservationID))
        {
            *data_len = 0;
            return IPMI_CC_INVALID_RESERVATION_ID;
        }
    }

    if (cache::paths.empty())
    {
        *data_len = 0;
        return IPMI_CC_SENSOR_INVALID;
    }

    ipmi::sel::ObjectPaths::const_iterator iter;

    // Check for the requested SEL Entry.
    if (requestData->selRecordID == ipmi::sel::firstEntry)
    {
        iter = cache::paths.begin();
    }
    else if (requestData->selRecordID == ipmi::sel::lastEntry)
    {
        iter = cache::paths.end();
    }
    else
    {
        std::string objPath = std::string(ipmi::sel::logBasePath) + "/" +
                              std::to_string(requestData->selRecordID);

        iter = std::find(cache::paths.begin(), cache::paths.end(), objPath);
        if (iter == cache::paths.end())
        {
            *data_len = 0;
            return IPMI_CC_SENSOR_INVALID;
        }
    }

    ipmi::sel::GetSELEntryResponse record{};

    // Convert the log entry into SEL record.
    try
    {
        record = ipmi::sel::convertLogEntrytoSEL(*iter);
    }
    catch (InternalFailure& e)
    {
        *data_len = 0;
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    catch (const std::runtime_error& e)
    {
        log<level::ERR>(e.what());
        *data_len = 0;
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    // Identify the next SEL record ID
    if (iter != cache::paths.end())
    {
        ++iter;
        if (iter == cache::paths.end())
        {
            record.nextRecordID = ipmi::sel::lastEntry;
        }
        else
        {
            namespace fs = std::filesystem;
            fs::path path(*iter);
            record.nextRecordID = static_cast<uint16_t>(
                std::stoul(std::string(path.filename().c_str())));
        }
    }
    else
    {
        record.nextRecordID = ipmi::sel::lastEntry;
    }

    if (requestData->readLength == ipmi::sel::entireRecord)
    {
        std::memcpy(response, &record, sizeof(record));
        *data_len = sizeof(record);
    }
    else
    {
        if (requestData->offset >= ipmi::sel::selRecordSize ||
            requestData->readLength > ipmi::sel::selRecordSize)
        {
            *data_len = 0;
            return IPMI_CC_INVALID_FIELD_REQUEST;
        }

        auto diff = ipmi::sel::selRecordSize - requestData->offset;
        auto readLength =
            std::min(diff, static_cast<int>(requestData->readLength));

        std::memcpy(response, &record.nextRecordID,
                    sizeof(record.nextRecordID));
        std::memcpy(static_cast<uint8_t*>(response) +
                        sizeof(record.nextRecordID),
                    &record.recordID + requestData->offset, readLength);
        *data_len = sizeof(record.nextRecordID) + readLength;
    }

    return IPMI_CC_OK;
}

ipmi_ret_t deleteSELEntry(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                          ipmi_request_t request, ipmi_response_t response,
                          ipmi_data_len_t data_len, ipmi_context_t context)
{
    if (*data_len != sizeof(ipmi::sel::DeleteSELEntryRequest))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    namespace fs = std::filesystem;
    auto requestData =
        reinterpret_cast<const ipmi::sel::DeleteSELEntryRequest*>(request);

    if (!checkSELReservation(requestData->reservationID))
    {
        *data_len = 0;
        return IPMI_CC_INVALID_RESERVATION_ID;
    }

    // Per the IPMI spec, need to cancel the reservation when a SEL entry is
    // deleted
    cancelSELReservation();

    try
    {
        ipmi::sel::readLoggingObjectPaths(cache::paths);
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        // readLoggingObjectPaths will throw exception if there are no error
        // log entries.
        *data_len = 0;
        return IPMI_CC_SENSOR_INVALID;
    }

    if (cache::paths.empty())
    {
        *data_len = 0;
        return IPMI_CC_SENSOR_INVALID;
    }

    ipmi::sel::ObjectPaths::const_iterator iter;
    uint16_t delRecordID = 0;

    if (requestData->selRecordID == ipmi::sel::firstEntry)
    {
        iter = cache::paths.begin();
        fs::path path(*iter);
        delRecordID = static_cast<uint16_t>(
            std::stoul(std::string(path.filename().c_str())));
    }
    else if (requestData->selRecordID == ipmi::sel::lastEntry)
    {
        iter = cache::paths.end();
        fs::path path(*iter);
        delRecordID = static_cast<uint16_t>(
            std::stoul(std::string(path.filename().c_str())));
    }
    else
    {
        std::string objPath = std::string(ipmi::sel::logBasePath) + "/" +
                              std::to_string(requestData->selRecordID);

        iter = std::find(cache::paths.begin(), cache::paths.end(), objPath);
        if (iter == cache::paths.end())
        {
            *data_len = 0;
            return IPMI_CC_SENSOR_INVALID;
        }
        delRecordID = requestData->selRecordID;
    }

    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    std::string service;

    try
    {
        service = ipmi::getService(bus, ipmi::sel::logDeleteIntf, *iter);
    }
    catch (const std::runtime_error& e)
    {
        log<level::ERR>(e.what());
        *data_len = 0;
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    auto methodCall = bus.new_method_call(service.c_str(), (*iter).c_str(),
                                          ipmi::sel::logDeleteIntf, "Delete");
    auto reply = bus.call(methodCall);
    if (reply.is_method_error())
    {
        *data_len = 0;
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    // Invalidate the cache of dbus entry objects.
    cache::paths.clear();
    std::memcpy(response, &delRecordID, sizeof(delRecordID));
    *data_len = sizeof(delRecordID);

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
        std::memcpy(response, &eraseProgress, sizeof(eraseProgress));
        *data_len = sizeof(eraseProgress);
        return IPMI_CC_OK;
    }

    // Per the IPMI spec, need to cancel any reservation when the SEL is cleared
    cancelSELReservation();

    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    ipmi::sel::ObjectPaths objectPaths;
    auto depth = 0;

    auto mapperCall =
        bus.new_method_call(ipmi::sel::mapperBusName, ipmi::sel::mapperObjPath,
                            ipmi::sel::mapperIntf, "GetSubTreePaths");
    mapperCall.append(ipmi::sel::logBasePath);
    mapperCall.append(depth);
    mapperCall.append(ipmi::sel::ObjectPaths({ipmi::sel::logEntryIntf}));

    try
    {
        auto reply = bus.call(mapperCall);
        if (reply.is_method_error())
        {
            std::memcpy(response, &eraseProgress, sizeof(eraseProgress));
            *data_len = sizeof(eraseProgress);
            return IPMI_CC_OK;
        }

        reply.read(objectPaths);
        if (objectPaths.empty())
        {
            std::memcpy(response, &eraseProgress, sizeof(eraseProgress));
            *data_len = sizeof(eraseProgress);
            return IPMI_CC_OK;
        }
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        std::memcpy(response, &eraseProgress, sizeof(eraseProgress));
        *data_len = sizeof(eraseProgress);
        return IPMI_CC_OK;
    }

    std::string service;

    try
    {
        service = ipmi::getService(bus, ipmi::sel::logDeleteIntf,
                                   objectPaths.front());
    }
    catch (const std::runtime_error& e)
    {
        log<level::ERR>(e.what());
        *data_len = 0;
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    for (const auto& iter : objectPaths)
    {
        auto methodCall = bus.new_method_call(
            service.c_str(), iter.c_str(), ipmi::sel::logDeleteIntf, "Delete");

        auto reply = bus.call(methodCall);
        if (reply.is_method_error())
        {
            *data_len = 0;
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
    }

    // Invalidate the cache of dbus entry objects.
    cache::paths.clear();
    std::memcpy(response, &eraseProgress, sizeof(eraseProgress));
    *data_len = sizeof(eraseProgress);
    return IPMI_CC_OK;
}
#endif // JOURNAL_SEL

ipmi_ret_t ipmi_storage_get_sel_time(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                     ipmi_request_t request,
                                     ipmi_response_t response,
                                     ipmi_data_len_t data_len,
                                     ipmi_context_t context)
{
    if (*data_len != 0)
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

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
        host_time_usec = variant_ns::get<uint64_t>(value);
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
    if (*data_len != sizeof(uint32_t))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
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
    if (*data_len != 0)
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    ipmi_ret_t rc = IPMI_CC_OK;
    unsigned short selResID = reserveSel();

    *data_len = sizeof(selResID);

    // Pack the actual response
    std::memcpy(response, &selResID, *data_len);

    return rc;
}

#ifdef JOURNAL_SEL
ipmi_ret_t ipmi_storage_add_sel(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request,
                                ipmi_response_t response,
                                ipmi_data_len_t data_len,
                                ipmi_context_t context)
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

    if (*data_len != sizeof(ipmi::sel::AddSELEntryRequest))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    ipmi::sel::AddSELEntryRequest* req =
        static_cast<ipmi::sel::AddSELEntryRequest*>(request);

    // Per the IPMI spec, need to cancel any reservation when a SEL entry is
    // added
    cancelSELReservation();

    if (req->recordType == ipmi::sel::systemEvent)
    {
        std::string sensorPath = getPathFromSensorNumber(req->sensorNum);
        std::vector<uint8_t> eventData(
            req->eventData, req->eventData + ipmi::sel::systemEventSize);
        bool assert =
            (req->eventType & ipmi::sel::deassertionEvent) ? false : true;
        uint16_t genId = req->generatorID;
        sdbusplus::message::message writeSEL = bus.new_method_call(
            ipmiSELObject, ipmiSELPath, ipmiSELAddInterface, "IpmiSelAdd");
        writeSEL.append(ipmiSELAddMessage, sensorPath, eventData, assert,
                        genId);
        try
        {
            sdbusplus::message::message writeSELResp = bus.call(writeSEL);
            writeSELResp.read(recordID);
        }
        catch (sdbusplus::exception_t& e)
        {
            log<level::ERR>(e.what());
            *data_len = 0;
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
    }
    else if (req->recordType >= ipmi::sel::oemTsEventFirst &&
             req->recordType <= ipmi::sel::oemEventLast)
    {
        std::vector<uint8_t> eventData;
        if (req->recordType <= ipmi::sel::oemTsEventLast)
        {
            ipmi::sel::AddSELEntryRequestOEMTimestamped* oemTsRequest =
                static_cast<ipmi::sel::AddSELEntryRequestOEMTimestamped*>(
                    request);
            eventData = std::vector<uint8_t>(oemTsRequest->eventData,
                                             oemTsRequest->eventData +
                                                 ipmi::sel::oemTsEventSize);
        }
        else
        {
            ipmi::sel::AddSELEntryRequestOEM* oemRequest =
                static_cast<ipmi::sel::AddSELEntryRequestOEM*>(request);
            eventData = std::vector<uint8_t>(oemRequest->eventData,
                                             oemRequest->eventData +
                                                 ipmi::sel::oemEventSize);
        }
        sdbusplus::message::message writeSEL = bus.new_method_call(
            ipmiSELObject, ipmiSELPath, ipmiSELAddInterface, "IpmiSelAddOem");
        writeSEL.append(ipmiSELAddMessage, eventData, req->recordType);
        try
        {
            sdbusplus::message::message writeSELResp = bus.call(writeSEL);
            writeSELResp.read(recordID);
        }
        catch (sdbusplus::exception_t& e)
        {
            log<level::ERR>(e.what());
            *data_len = 0;
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
    }
    else
    {
        *data_len = 0;
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    *static_cast<uint16_t*>(response) = recordID;
    *data_len = sizeof(recordID);
    return IPMI_CC_OK;
}
#else  // JOURNAL_SEL not used
ipmi_ret_t ipmi_storage_add_sel(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request,
                                ipmi_response_t response,
                                ipmi_data_len_t data_len,
                                ipmi_context_t context)
{
    if (*data_len != sizeof(ipmi_add_sel_request_t))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    ipmi_ret_t rc = IPMI_CC_OK;
    ipmi_add_sel_request_t* p = (ipmi_add_sel_request_t*)request;
    uint16_t recordid;

    // Per the IPMI spec, need to cancel the reservation when a SEL entry is
    // added
    cancelSELReservation();

    recordid = ((uint16_t)p->eventdata[1] << 8) | p->eventdata[2];

    *data_len = sizeof(recordid);

    // Pack the actual response
    std::memcpy(response, &p->eventdata[1], 2);

    // Hostboot sends SEL with OEM record type 0xDE to indicate that there is
    // a maintenance procedure associated with eSEL record.
    static constexpr auto procedureType = 0xDE;
    if (p->recordtype == procedureType)
    {
        // In the OEM record type 0xDE, byte 11 in the SEL record indicate the
        // procedure number.
        createProcedureLogEntry(p->sensortype);
    }

    return rc;
}
#endif // JOURNAL_SEL

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

#ifndef JOURNAL_SEL
    // <Delete SEL Entry>
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_DELETE_SEL, NULL,
                           deleteSELEntry, PRIVILEGE_OPERATOR);
#endif

    // <Add SEL Entry>
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_ADD_SEL, NULL,
                           ipmi_storage_add_sel, PRIVILEGE_OPERATOR);
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
