#include "storagehandler.hpp"

#include "fruread.hpp"
#include "read_fru_data.hpp"
#include "selutility.hpp"
#include "sensorhandler.hpp"
#include "storageaddsel.hpp"

#include <arpa/inet.h>
#include <mapper.h>
#include <systemd/sd-bus.h>

#include <algorithm>
#include <boost/process.hpp>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/server.hpp>
#include <sdrutils.hpp>
#include <string>
#include <string_view>
#include <variant>
#include <xyz/openbmc_project/Common/error.hpp>

void register_netfn_storage_functions() __attribute__((constructor));

unsigned int g_sel_time = 0xFFFFFFFF;
namespace ipmi
{
namespace sensor
{
extern const IdInfoMap sensors;
} // namespace sensor
} // namespace ipmi

extern const FruMap frus;
constexpr uint8_t eventDataSize = 3;
namespace
{
constexpr auto TIME_INTERFACE = "xyz.openbmc_project.Time.EpochTime";
constexpr auto HOST_TIME_PATH = "/xyz/openbmc_project/time/host";
constexpr auto DBUS_PROPERTIES = "org.freedesktop.DBus.Properties";
constexpr auto PROPERTY_ELAPSED = "Elapsed";

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
namespace ipmi::sel::erase_time
{
static constexpr const char* selEraseTimestamp = "/var/lib/ipmi/sel_erase_time";

void save()
{
    // open the file, creating it if necessary
    int fd = open(selEraseTimestamp, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
    if (fd < 0)
    {
        std::cerr << "Failed to open file\n";
        return;
    }

    // update the file timestamp to the current time
    if (futimens(fd, NULL) < 0)
    {
        std::cerr << "Failed to update timestamp: "
                  << std::string(strerror(errno));
    }
    close(fd);
}

int get()
{
    struct stat st;
    // default to an invalid timestamp
    int timestamp = ::ipmi::sel::invalidTimeStamp;

    int fd = open(selEraseTimestamp, O_RDWR | O_CLOEXEC, 0644);
    if (fd < 0)
    {
        return timestamp;
    }

    if (fstat(fd, &st) >= 0)
    {
        timestamp = st.st_mtime;
    }

    return timestamp;
}
} // namespace ipmi::sel::erase_time

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

ipmi::RspType<uint8_t // erase status
              >
    clearSEL(uint16_t reservationID, const std::array<char, 3>& clr,
             uint8_t eraseOperation)
{
    static constexpr std::array<char, 3> clrOk = {'C', 'L', 'R'};
    if (clr != clrOk)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    if (!checkSELReservation(reservationID))
    {
        return ipmi::responseInvalidReservationId();
    }

    /*
     * Erasure status cannot be fetched from DBUS, so always return erasure
     * status as `erase completed`.
     */
    if (eraseOperation == ipmi::sel::getEraseStatus)
    {
        return ipmi::responseSuccess(
            static_cast<uint8_t>(ipmi::sel::eraseComplete));
    }

    // Per the IPMI spec, need to cancel any reservation when the SEL is cleared
    cancelSELReservation();

    // Save the erase time
    ipmi::sel::erase_time::save();

    // Clear the SEL by by rotating the journal to start a new file then
    // vacuuming to keep only the new file
    if (boost::process::system("/bin/journalctl", "--rotate") != 0)
    {
        return ipmi::responseUnspecifiedError();
    }
    if (boost::process::system("/bin/journalctl", "--vacuum-files=1") != 0)
    {
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(
        static_cast<uint8_t>(ipmi::sel::eraseComplete));
}

#else // JOURNAL_SEL not used
/** @brief implements the get SEL Info command
 *  @returns IPMI completion code plus response data
 *   - selVersion - SEL revision
 *   - entries    - Number of log entries in SEL.
 *   - freeSpace  - Free Space in bytes.
 *   - addTimeStamp - Most recent addition timestamp
 *   - eraseTimeStamp - Most recent erase timestamp
 *   - operationSupport - Reserve & Delete SEL operations supported
 */

ipmi::RspType<uint8_t,  // SEL revision.
              uint16_t, // number of log entries in SEL.
              uint16_t, // free Space in bytes.
              uint32_t, // most recent addition timestamp
              uint32_t, // most recent erase timestamp.

              bool,    // SEL allocation info supported
              bool,    // reserve SEL supported
              bool,    // partial Add SEL Entry supported
              bool,    // delete SEL supported
              uint3_t, // reserved
              bool     // overflow flag
              >
    ipmiStorageGetSelInfo()
{
    uint16_t entries = 0;
    // Most recent addition timestamp.
    uint32_t addTimeStamp = ipmi::sel::invalidTimeStamp;

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

    if (!cache::paths.empty())
    {
        entries = static_cast<uint16_t>(cache::paths.size());

        try
        {
            addTimeStamp = static_cast<uint32_t>(
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

    constexpr uint8_t selVersion = ipmi::sel::selVersion;
    constexpr uint16_t freeSpace = 0xFFFF;
    constexpr uint32_t eraseTimeStamp = ipmi::sel::invalidTimeStamp;
    constexpr uint3_t reserved{0};

    return ipmi::responseSuccess(
        selVersion, entries, freeSpace, addTimeStamp, eraseTimeStamp,
        ipmi::sel::operationSupport::getSelAllocationInfo,
        ipmi::sel::operationSupport::reserveSel,
        ipmi::sel::operationSupport::partialAddSelEntry,
        ipmi::sel::operationSupport::deleteSel, reserved,
        ipmi::sel::operationSupport::overflow);
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

/** @brief implements the delete SEL entry command
 * @request
 *   - reservationID; // reservation ID.
 *   - selRecordID;   // SEL record ID.
 *
 *  @returns ipmi completion code plus response data
 *   - Record ID of the deleted record
 */
ipmi::RspType<uint16_t // deleted record ID
              >
    deleteSELEntry(uint16_t reservationID, uint16_t selRecordID)
{

    namespace fs = std::filesystem;

    if (!checkSELReservation(reservationID))
    {
        return ipmi::responseInvalidReservationId();
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
        return ipmi::responseSensorInvalid();
    }

    if (cache::paths.empty())
    {
        return ipmi::responseSensorInvalid();
    }

    ipmi::sel::ObjectPaths::const_iterator iter;
    uint16_t delRecordID = 0;

    if (selRecordID == ipmi::sel::firstEntry)
    {
        iter = cache::paths.begin();
        fs::path path(*iter);
        delRecordID = static_cast<uint16_t>(
            std::stoul(std::string(path.filename().c_str())));
    }
    else if (selRecordID == ipmi::sel::lastEntry)
    {
        iter = cache::paths.end();
        fs::path path(*iter);
        delRecordID = static_cast<uint16_t>(
            std::stoul(std::string(path.filename().c_str())));
    }
    else
    {
        std::string objPath = std::string(ipmi::sel::logBasePath) + "/" +
                              std::to_string(selRecordID);

        iter = std::find(cache::paths.begin(), cache::paths.end(), objPath);
        if (iter == cache::paths.end())
        {
            return ipmi::responseSensorInvalid();
        }
        delRecordID = selRecordID;
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
        return ipmi::responseUnspecifiedError();
    }

    auto methodCall = bus.new_method_call(service.c_str(), (*iter).c_str(),
                                          ipmi::sel::logDeleteIntf, "Delete");
    auto reply = bus.call(methodCall);
    if (reply.is_method_error())
    {
        return ipmi::responseUnspecifiedError();
    }

    // Invalidate the cache of dbus entry objects.
    cache::paths.clear();

    return ipmi::responseSuccess(delRecordID);
}

/** @brief implements the Clear SEL command
 * @request
 *   - reservationID   // Reservation ID.
 *   - clr             // char array { 'C'(0x43h), 'L'(0x4Ch), 'R'(0x52h) }
 *   - eraseOperation; // requested operation.
 *
 *  @returns ipmi completion code plus response data
 *   - erase status
 */

ipmi::RspType<uint8_t // erase status
              >
    clearSEL(uint16_t reservationID, const std::array<char, 3>& clr,
             uint8_t eraseOperation)
{
    static constexpr std::array<char, 3> clrOk = {'C', 'L', 'R'};
    if (clr != clrOk)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    if (!checkSELReservation(reservationID))
    {
        return ipmi::responseInvalidReservationId();
    }

    /*
     * Erasure status cannot be fetched from DBUS, so always return erasure
     * status as `erase completed`.
     */
    if (eraseOperation == ipmi::sel::getEraseStatus)
    {
        return ipmi::responseSuccess(
            static_cast<uint8_t>(ipmi::sel::eraseComplete));
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
            return ipmi::responseSuccess(
                static_cast<uint8_t>(ipmi::sel::eraseComplete));
        }

        reply.read(objectPaths);
        if (objectPaths.empty())
        {
            return ipmi::responseSuccess(
                static_cast<uint8_t>(ipmi::sel::eraseComplete));
        }
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        return ipmi::responseSuccess(
            static_cast<uint8_t>(ipmi::sel::eraseComplete));
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
        return ipmi::responseUnspecifiedError();
    }

    for (const auto& iter : objectPaths)
    {
        auto methodCall = bus.new_method_call(
            service.c_str(), iter.c_str(), ipmi::sel::logDeleteIntf, "Delete");

        auto reply = bus.call(methodCall);
        if (reply.is_method_error())
        {
            return ipmi::responseUnspecifiedError();
        }
    }

    // Invalidate the cache of dbus entry objects.
    cache::paths.clear();
    return ipmi::responseSuccess(
        static_cast<uint8_t>(ipmi::sel::eraseComplete));
}
#endif

/** @brief implements the get SEL time command
 *  @returns IPMI completion code plus response data
 *   -current time
 */
ipmi::RspType<uint32_t> // current time
    ipmiStorageGetSelTime()
{
    using namespace std::chrono;
    uint64_t host_time_usec = 0;
    std::stringstream hostTime;

    try
    {
        sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
        auto service = ipmi::getService(bus, TIME_INTERFACE, HOST_TIME_PATH);
        std::variant<uint64_t> value;

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
            return ipmi::responseUnspecifiedError();
        }
        reply.read(value);
        host_time_usec = std::get<uint64_t>(value);
    }
    catch (InternalFailure& e)
    {
        log<level::ERR>(e.what());
        return ipmi::responseUnspecifiedError();
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(e.what());
        return ipmi::responseUnspecifiedError();
    }

    hostTime << "Host time:"
             << duration_cast<seconds>(microseconds(host_time_usec)).count();
    log<level::DEBUG>(hostTime.str().c_str());

    // Time is really long int but IPMI wants just uint32. This works okay until
    // the number of seconds since 1970 overflows uint32 size.. Still a whole
    // lot of time here to even think about that.
    return ipmi::responseSuccess(
        duration_cast<seconds>(microseconds(host_time_usec)).count());
}

/** @brief implements the set SEL time command
 *  @param selDeviceTime - epoch time
 *        -local time as the number of seconds from 00:00:00, January 1, 1970
 *  @returns IPMI completion code
 */
ipmi::RspType<> ipmiStorageSetSelTime(uint32_t selDeviceTime)
{
    using namespace std::chrono;
    microseconds usec{seconds(selDeviceTime)};

    try
    {
        sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
        auto service = ipmi::getService(bus, TIME_INTERFACE, HOST_TIME_PATH);
        std::variant<uint64_t> value{usec.count()};

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
            return ipmi::responseUnspecifiedError();
        }
    }
    catch (InternalFailure& e)
    {
        log<level::ERR>(e.what());
        return ipmi::responseUnspecifiedError();
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(e.what());
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess();
}

/** @brief implements the reserve SEL command
 *  @returns IPMI completion code plus response data
 *   - SEL reservation ID.
 */
ipmi::RspType<uint16_t> ipmiStorageReserveSel()
{
    return ipmi::responseSuccess(reserveSel());
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
/** @brief implements the Add SEL entry command
 * @request
 *
 *   - recordID      ID used for SEL Record access
 *   - recordType    Record Type
 *   - timeStamp     Time when event was logged. LS byte first
 *   - generatorID   software ID if event was generated from
 *                   system software
 *   - evmRev        event message format version
 *   - sensorType    sensor type code for service that generated
 *                   the event
 *   - sensorNumber  number of sensors that generated the event
 *   - eventDir     event dir
 *   - eventData    event data field contents
 *
 *  @returns ipmi completion code plus response data
 *   - RecordID of the Added SEL entry
 */
ipmi::RspType<uint16_t // recordID of the Added SEL entry
              >
    ipmiStorageAddSEL(uint16_t recordID, uint8_t recordType, uint32_t timeStamp,
                      uint16_t generatorID, uint8_t evmRev, uint8_t sensorType,
                      uint8_t sensorNumber, uint8_t eventDir,
                      std::array<uint8_t, eventDataSize> eventData)
{
    // Per the IPMI spec, need to cancel the reservation when a SEL entry is
    // added
    cancelSELReservation();
    // Hostboot sends SEL with OEM record type 0xDE to indicate that there is
    // a maintenance procedure associated with eSEL record.
    static constexpr auto procedureType = 0xDE;
    if (recordType == procedureType)
    {
        // In the OEM record type 0xDE, byte 11 in the SEL record indicate the
        // procedure number.
        createProcedureLogEntry(sensorType);
    }

    return ipmi::responseSuccess(recordID);
}
#endif // JOURNAL_SEL

/** @brief implements the get FRU Inventory Area Info command
 *
 *  @returns IPMI completion code plus response data
 *   - FRU Inventory area size in bytes,
 *   - access bit
 **/
ipmi::RspType<uint16_t, // FRU Inventory area size in bytes,
              uint8_t   // access size (bytes / words)
              >
    ipmiStorageGetFruInvAreaInfo(uint8_t fruID)
{

    auto iter = frus.find(fruID);
    if (iter == frus.end())
    {
        return ipmi::responseSensorInvalid();
    }

    try
    {
        return ipmi::responseSuccess(
            static_cast<uint16_t>(getFruAreaData(fruID).size()),
            static_cast<uint8_t>(AccessMode::bytes));
    }
    catch (const InternalFailure& e)
    {
        log<level::ERR>(e.what());
        return ipmi::responseUnspecifiedError();
    }
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

ipmi::RspType<uint8_t,  // SDR version
              uint16_t, // record count LS first
              uint16_t, // free space in bytes, LS first
              uint32_t, // addition timestamp LS first
              uint32_t, // deletion timestamp LS first
              uint8_t>  // operation Support
    ipmiGetRepositoryInfo()
{

    constexpr uint8_t sdrVersion = 0x51;
    constexpr uint16_t freeSpace = 0xFFFF;
    constexpr uint32_t additionTimestamp = 0x0;
    constexpr uint32_t deletionTimestamp = 0x0;
    constexpr uint8_t operationSupport = 0;

    uint16_t records = frus.size() + ipmi::sensor::sensors.size();

    return ipmi::responseSuccess(sdrVersion, records, freeSpace,
                                 additionTimestamp, deletionTimestamp,
                                 operationSupport);
}

void register_netfn_storage_functions()
{
    // <Wildcard Command>
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_WILDCARD, NULL,
                           ipmi_storage_wildcard, PRIVILEGE_USER);
#ifdef JOURNAL_SEL
    // <Get SEL Info>
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_GET_SEL_INFO, NULL,
                           getSELInfo, PRIVILEGE_USER);

#else
    // <Get SEL Info>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetSelInfo, ipmi::Privilege::User,
                          ipmiStorageGetSelInfo);
#endif
    // <Get SEL Time>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetSelTime, ipmi::Privilege::User,
                          ipmiStorageGetSelTime);

    // <Set SEL Time>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdSetSelTime,
                          ipmi::Privilege::Operator, ipmiStorageSetSelTime);

    // <Reserve SEL>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdReserveSel, ipmi::Privilege::User,
                          ipmiStorageReserveSel);
    // <Get SEL Entry>
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_GET_SEL_ENTRY, NULL,
                           getSELEntry, PRIVILEGE_USER);

#ifndef JOURNAL_SEL
    // <Delete SEL Entry>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdDeleteSelEntry,
                          ipmi::Privilege::Operator, deleteSELEntry);
    // <Add SEL Entry>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdAddSelEntry,
                          ipmi::Privilege::Operator, ipmiStorageAddSEL);
#else
    // <Add SEL Entry>
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_ADD_SEL, NULL,
                           ipmi_storage_add_sel, PRIVILEGE_OPERATOR);
#endif
    // <Clear SEL>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdClearSel, ipmi::Privilege::Operator,
                          clearSEL);

    // <Get FRU Inventory Area Info>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetFruInventoryAreaInfo,
                          ipmi::Privilege::User, ipmiStorageGetFruInvAreaInfo);

    // <READ FRU Data>
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_READ_FRU_DATA, NULL,
                           ipmi_storage_read_fru_data, PRIVILEGE_USER);

    // <Get Repository Info>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetSdrRepositoryInfo,
                          ipmi::Privilege::User, ipmiGetRepositoryInfo);

    // <Reserve SDR Repository>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdReserveSdrRepository,
                          ipmi::Privilege::User, ipmiSensorReserveSdr);

    // <Get SDR>
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_GET_SDR, nullptr,
                           ipmi_sen_get_sdr, PRIVILEGE_USER);

    ipmi::fru::registerCallbackHandler();
    return;
}
