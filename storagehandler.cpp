#include "config.h"

#include "storagehandler.hpp"

#include "fruread.hpp"
#include "read_fru_data.hpp"
#include "selutility.hpp"
#include "sensorhandler.hpp"
#include "storageaddsel.hpp"

#include <arpa/inet.h>
#include <systemd/sd-bus.h>

#include <ipmid/api.hpp>
#include <ipmid/entity_map_json.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/server.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/Logging/SEL/error.hpp>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <optional>
#include <string>
#include <variant>

void register_netfn_storage_functions() __attribute__((constructor));

unsigned int g_sel_time = 0xFFFFFFFF;
namespace ipmi
{
namespace sensor
{
extern const IdInfoMap sensors;
} // namespace sensor
} // namespace ipmi
extern const ipmi::sensor::InvObjectIDMap invSensors;
extern const FruMap frus;
constexpr uint8_t eventDataSize = 3;
namespace
{
constexpr auto SystemdTimeService = "org.freedesktop.timedate1";
constexpr auto SystemdTimePath = "/org/freedesktop/timedate1";
constexpr auto SystemdTimeInterface = "org.freedesktop.timedate1";

constexpr auto TIME_INTERFACE = "xyz.openbmc_project.Time.EpochTime";
constexpr auto BMC_TIME_PATH = "/xyz/openbmc_project/time/bmc";
constexpr auto DBUS_PROPERTIES = "org.freedesktop.DBus.Properties";
constexpr auto PROPERTY_ELAPSED = "Elapsed";
} // namespace

using InternalFailure =
    sdbusplus::error::xyz::openbmc_project::common::InternalFailure;
using namespace phosphor::logging;
using namespace ipmi::fru;
using namespace xyz::openbmc_project::logging::sel;
using SELCreated =
    sdbusplus::error::xyz::openbmc_project::logging::sel::Created;

using SELRecordID = uint16_t;
using SELEntry = ipmi::sel::SELEventRecordFormat;
using SELCacheMap = std::map<SELRecordID, SELEntry>;

SELCacheMap selCacheMap __attribute__((init_priority(101)));
bool selCacheMapInitialized;
std::unique_ptr<sdbusplus::bus::match_t> selAddedMatch
    __attribute__((init_priority(101)));
std::unique_ptr<sdbusplus::bus::match_t> selRemovedMatch
    __attribute__((init_priority(101)));
std::unique_ptr<sdbusplus::bus::match_t> selUpdatedMatch
    __attribute__((init_priority(101)));

static inline uint16_t getLoggingId(const std::string& p)
{
    namespace fs = std::filesystem;
    fs::path entryPath(p);
    return std::stoul(entryPath.filename().string());
}

static inline std::string getLoggingObjPath(uint16_t id)
{
    return std::string(ipmi::sel::logBasePath) + "/" + std::to_string(id);
}

std::optional<std::pair<uint16_t, SELEntry>>
    parseLoggingEntry(const std::string& p)
{
    try
    {
        auto id = getLoggingId(p);
        ipmi::sel::GetSELEntryResponse record{};
        record = ipmi::sel::convertLogEntrytoSEL(p);
        return std::pair<uint16_t, SELEntry>({id, std::move(record.event)});
    }
    catch (const std::exception& e)
    {
        fprintf(stderr, "Failed to convert %s to SEL: %s\n", p.c_str(),
                e.what());
    }
    return std::nullopt;
}

static void selAddedCallback(sdbusplus::message_t& m)
{
    sdbusplus::message::object_path objPath;
    try
    {
        m.read(objPath);
    }
    catch (const sdbusplus::exception_t& e)
    {
        lg2::error("Failed to read object path");
        return;
    }
    std::string p = objPath;
    auto entry = parseLoggingEntry(p);
    if (entry)
    {
        selCacheMap.insert(std::move(*entry));
    }
}

static void selRemovedCallback(sdbusplus::message_t& m)
{
    sdbusplus::message::object_path objPath;
    try
    {
        m.read(objPath);
    }
    catch (const sdbusplus::exception_t& e)
    {
        lg2::error("Failed to read object path");
    }
    try
    {
        std::string p = objPath;
        selCacheMap.erase(getLoggingId(p));
    }
    catch (const std::invalid_argument& e)
    {
        lg2::error("Invalid logging entry ID");
    }
}

static void selUpdatedCallback(sdbusplus::message_t& m)
{
    std::string p = m.get_path();
    auto entry = parseLoggingEntry(p);
    if (entry)
    {
        selCacheMap.insert_or_assign(entry->first, std::move(entry->second));
    }
}

void registerSelCallbackHandler()
{
    using namespace sdbusplus::bus::match::rules;
    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};
    if (!selAddedMatch)
    {
        selAddedMatch = std::make_unique<sdbusplus::bus::match_t>(
            bus, interfacesAdded(ipmi::sel::logWatchPath),
            std::bind(selAddedCallback, std::placeholders::_1));
    }
    if (!selRemovedMatch)
    {
        selRemovedMatch = std::make_unique<sdbusplus::bus::match_t>(
            bus, interfacesRemoved(ipmi::sel::logWatchPath),
            std::bind(selRemovedCallback, std::placeholders::_1));
    }
    if (!selUpdatedMatch)
    {
        selUpdatedMatch = std::make_unique<sdbusplus::bus::match_t>(
            bus,
            type::signal() + member("PropertiesChanged"s) +
                interface("org.freedesktop.DBus.Properties"s) +
                argN(0, ipmi::sel::logEntryIntf),
            std::bind(selUpdatedCallback, std::placeholders::_1));
    }
}

void initSELCache()
{
    registerSelCallbackHandler();
    ipmi::sel::ObjectPaths paths;
    try
    {
        ipmi::sel::readLoggingObjectPaths(paths);
    }
    catch (const sdbusplus::exception_t& e)
    {
        lg2::error("Failed to get logging object paths");
        return;
    }
    for (const auto& p : paths)
    {
        auto entry = parseLoggingEntry(p);
        if (entry)
        {
            selCacheMap.insert(std::move(*entry));
        }
    }
    selCacheMapInitialized = true;
}

/**
 * @enum Device access mode
 */
enum class AccessMode
{
    bytes, ///< Device is accessed by bytes
    words  ///< Device is accessed by words
};

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

              bool,     // SEL allocation info supported
              bool,     // reserve SEL supported
              bool,     // partial Add SEL Entry supported
              bool,     // delete SEL supported
              uint3_t,  // reserved
              bool      // overflow flag
              >
    ipmiStorageGetSelInfo()
{
    uint16_t entries = 0;
    // Most recent addition timestamp.
    uint32_t addTimeStamp = ipmi::sel::invalidTimeStamp;

    if (!selCacheMapInitialized)
    {
        // In case the initSELCache() fails, try it again
        initSELCache();
    }
    if (!selCacheMap.empty())
    {
        entries = static_cast<uint16_t>(selCacheMap.size());

        try
        {
            auto objPath = getLoggingObjPath(selCacheMap.rbegin()->first);
            addTimeStamp = static_cast<uint32_t>(
                (ipmi::sel::getEntryTimeStamp(objPath).count()));
        }
        catch (const InternalFailure& e)
        {}
        catch (const std::runtime_error& e)
        {
            lg2::error("runtime error: {ERROR}", "ERROR", e);
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

ipmi_ret_t getSELEntry(ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t request,
                       ipmi_response_t response, ipmi_data_len_t data_len,
                       ipmi_context_t)
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

    if (!selCacheMapInitialized)
    {
        // In case the initSELCache() fails, try it again
        initSELCache();
    }

    if (selCacheMap.empty())
    {
        *data_len = 0;
        return IPMI_CC_SENSOR_INVALID;
    }

    SELCacheMap::const_iterator iter;

    // Check for the requested SEL Entry.
    if (requestData->selRecordID == ipmi::sel::firstEntry)
    {
        iter = selCacheMap.begin();
    }
    else if (requestData->selRecordID == ipmi::sel::lastEntry)
    {
        if (selCacheMap.size() > 1)
        {
            iter = selCacheMap.end();
            --iter;
        }
        else
        {
            // Only one entry exists, return the first
            iter = selCacheMap.begin();
        }
    }
    else
    {
        iter = selCacheMap.find(requestData->selRecordID);
        if (iter == selCacheMap.end())
        {
            *data_len = 0;
            return IPMI_CC_SENSOR_INVALID;
        }
    }

    ipmi::sel::GetSELEntryResponse record{0, iter->second};
    // Identify the next SEL record ID
    ++iter;
    if (iter == selCacheMap.end())
    {
        record.nextRecordID = ipmi::sel::lastEntry;
    }
    else
    {
        record.nextRecordID = iter->first;
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
                    &record.event.eventRecord.recordID + requestData->offset,
                    readLength);
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

    if (!selCacheMapInitialized)
    {
        // In case the initSELCache() fails, try it again
        initSELCache();
    }

    if (selCacheMap.empty())
    {
        return ipmi::responseSensorInvalid();
    }

    SELCacheMap::const_iterator iter;
    uint16_t delRecordID = 0;

    if (selRecordID == ipmi::sel::firstEntry)
    {
        delRecordID = selCacheMap.begin()->first;
    }
    else if (selRecordID == ipmi::sel::lastEntry)
    {
        delRecordID = selCacheMap.rbegin()->first;
    }
    else
    {
        delRecordID = selRecordID;
    }

    iter = selCacheMap.find(delRecordID);
    if (iter == selCacheMap.end())
    {
        return ipmi::responseSensorInvalid();
    }

    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};
    std::string service;

    auto objPath = getLoggingObjPath(iter->first);
    try
    {
        service = ipmi::getService(bus, ipmi::sel::logDeleteIntf, objPath);
    }
    catch (const std::runtime_error& e)
    {
        lg2::error("runtime error: {ERROR}", "ERROR", e);
        return ipmi::responseUnspecifiedError();
    }

    auto methodCall = bus.new_method_call(service.c_str(), objPath.c_str(),
                                          ipmi::sel::logDeleteIntf, "Delete");
    try
    {
        auto reply = bus.call(methodCall);
    }
    catch (const std::exception& e)
    {
        return ipmi::responseUnspecifiedError();
    }

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

    // Check that initiate erase is correct
    if (eraseOperation != ipmi::sel::initiateErase)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    // Per the IPMI spec, need to cancel any reservation when the SEL is cleared
    cancelSELReservation();

    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};
    auto service = ipmi::getService(bus, ipmi::sel::logIntf, ipmi::sel::logObj);
    auto method =
        bus.new_method_call(service.c_str(), ipmi::sel::logObj,
                            ipmi::sel::logIntf, ipmi::sel::logDeleteAllMethod);
    try
    {
        bus.call_noreply(method);
    }
    catch (const sdbusplus::exception_t& e)
    {
        lg2::error("Error eraseAll: {ERROR}", "ERROR", e);
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(
        static_cast<uint8_t>(ipmi::sel::eraseComplete));
}

/** @brief implements the get SEL time command
 *  @returns IPMI completion code plus response data
 *   -current time
 */
ipmi::RspType<uint32_t> // current time
    ipmiStorageGetSelTime()
{
    using namespace std::chrono;
    uint64_t bmc_time_usec = 0;
    std::stringstream bmcTime;

    try
    {
        sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};
        auto service = ipmi::getService(bus, TIME_INTERFACE, BMC_TIME_PATH);
        auto propValue = ipmi::getDbusProperty(
            bus, service, BMC_TIME_PATH, TIME_INTERFACE, PROPERTY_ELAPSED);
        bmc_time_usec = std::get<uint64_t>(propValue);
    }
    catch (const InternalFailure& e)
    {
        lg2::error("Internal Failure: {ERROR}", "ERROR", e);
        return ipmi::responseUnspecifiedError();
    }
    catch (const std::exception& e)
    {
        lg2::error("exception message: {ERROR}", "ERROR", e);
        return ipmi::responseUnspecifiedError();
    }

    lg2::debug("BMC time: {BMC_TIME}", "BMC_TIME",
               duration_cast<seconds>(microseconds(bmc_time_usec)).count());

    // Time is really long int but IPMI wants just uint32. This works okay until
    // the number of seconds since 1970 overflows uint32 size.. Still a whole
    // lot of time here to even think about that.
    return ipmi::responseSuccess(
        duration_cast<seconds>(microseconds(bmc_time_usec)).count());
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
        sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};
        bool ntp = std::get<bool>(
            ipmi::getDbusProperty(bus, SystemdTimeService, SystemdTimePath,
                                  SystemdTimeInterface, "NTP"));
        if (ntp)
        {
            return ipmi::responseCommandNotAvailable();
        }

        auto service = ipmi::getService(bus, TIME_INTERFACE, BMC_TIME_PATH);
        std::variant<uint64_t> value{(uint64_t)usec.count()};

        // Set bmc time
        auto method = bus.new_method_call(service.c_str(), BMC_TIME_PATH,
                                          DBUS_PROPERTIES, "Set");

        method.append(TIME_INTERFACE, PROPERTY_ELAPSED, value);
        auto reply = bus.call(method);
    }
    catch (const InternalFailure& e)
    {
        lg2::error("Internal Failure: {ERROR}", "ERROR", e);
        return ipmi::responseUnspecifiedError();
    }
    catch (const std::exception& e)
    {
        lg2::error("exception message: {ERROR}", "ERROR", e);
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess();
}

/** @brief implements the get SEL timezone command
 *  @returns IPMI completion code plus response data
 *   -current timezone
 */
ipmi::RspType<int16_t> ipmiStorageGetSelTimeUtcOffset()
{
    time_t timep;
    struct tm* gmTime;
    struct tm* localTime;

    time(&timep);
    localTime = localtime(&timep);
    auto validLocalTime = mktime(localTime);
    gmTime = gmtime(&timep);
    auto validGmTime = mktime(gmTime);
    auto timeEquation = (validLocalTime - validGmTime) / 60;

    return ipmi::responseSuccess(timeEquation);
}

/** @brief implements the reserve SEL command
 *  @returns IPMI completion code plus response data
 *   - SEL reservation ID.
 */
ipmi::RspType<uint16_t> ipmiStorageReserveSel()
{
    return ipmi::responseSuccess(reserveSel());
}

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
    ipmiStorageAddSEL(uint16_t recordID, uint8_t recordType,
                      [[maybe_unused]] uint32_t timeStamp, uint16_t generatorID,
                      [[maybe_unused]] uint8_t evmRev, uint8_t sensorType,
                      uint8_t sensorNumber, uint8_t eventDir,
                      std::array<uint8_t, eventDataSize> eventData)
{
    std::string objpath;
    static constexpr auto systemRecordType = 0x02;
    // Hostboot sends SEL with OEM record type 0xDE to indicate that there is
    // a maintenance procedure associated with eSEL record.
    static constexpr auto procedureType = 0xDE;
    cancelSELReservation();
    if (recordType == systemRecordType)
    {
        for (const auto& it : invSensors)
        {
            if (it.second.sensorID == sensorNumber)
            {
                objpath = it.first;
                break;
            }
        }
        auto selDataStr = ipmi::sel::toHexStr(eventData);

        bool assert = (eventDir & 0x80) ? false : true;

        recordID = report<SELCreated>(
            Created::RECORD_TYPE(recordType),
            Created::GENERATOR_ID(generatorID),
            Created::SENSOR_DATA(selDataStr.c_str()),
            Created::EVENT_DIR(assert), Created::SENSOR_PATH(objpath.c_str()));
    }
#ifdef OPEN_POWER_SUPPORT
    else if (recordType == procedureType)
    {
        // In the OEM record type 0xDE, byte 11 in the SEL record indicate the
        // procedure number.
        createProcedureLogEntry(sensorType);
    }
#endif

    return ipmi::responseSuccess(recordID);
}

bool isFruPresent(ipmi::Context::ptr& ctx, const std::string& fruPath)
{
    using namespace ipmi::fru;

    std::string service;
    boost::system::error_code ec =
        getService(ctx, invItemInterface, invObjPath + fruPath, service);
    if (!ec)
    {
        bool result;
        ec = ipmi::getDbusProperty(ctx, service, invObjPath + fruPath,
                                   invItemInterface, itemPresentProp, result);
        if (!ec)
        {
            return result;
        }
    }

    ipmi::ObjectValueTree managedObjects;
    ec = getManagedObjects(ctx, "xyz.openbmc_project.EntityManager",
                           "/xyz/openbmc_project/inventory", managedObjects);
    if (!ec)
    {
        auto connection = managedObjects.find(fruPath);
        if (connection != managedObjects.end())
        {
            return true;
        }
    }

    return false;
}

/** @brief implements the get FRU Inventory Area Info command
 *
 *  @returns IPMI completion code plus response data
 *   - FRU Inventory area size in bytes,
 *   - access bit
 **/
ipmi::RspType<uint16_t, // FRU Inventory area size in bytes,
              uint8_t   // access size (bytes / words)
              >
    ipmiStorageGetFruInvAreaInfo(ipmi::Context::ptr ctx, uint8_t fruID)
{
    auto iter = frus.find(fruID);
    if (iter == frus.end())
    {
        return ipmi::responseSensorInvalid();
    }

    auto path = iter->second[0].path;
    if (!isFruPresent(ctx, path))
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
        lg2::error("Internal Failure: {ERROR}", "ERROR", e);
        return ipmi::responseUnspecifiedError();
    }
}

/**@brief implements the Read FRU Data command
 * @param fruDeviceId - FRU device ID. FFh = reserved
 * @param offset      - FRU inventory offset to read
 * @param readCount   - count to read
 *
 * @return IPMI completion code plus response data
 * - returnCount - response data count.
 * - data        -  response data
 */
ipmi::RspType<uint8_t,              // count returned
              std::vector<uint8_t>> // FRU data
    ipmiStorageReadFruData(uint8_t fruDeviceId, uint16_t offset,
                           uint8_t readCount)
{
    if (fruDeviceId == 0xFF)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    auto iter = frus.find(fruDeviceId);
    if (iter == frus.end())
    {
        return ipmi::responseSensorInvalid();
    }

    try
    {
        const auto& fruArea = getFruAreaData(fruDeviceId);
        auto size = fruArea.size();

        if (offset >= size)
        {
            return ipmi::responseParmOutOfRange();
        }

        // Write the count of response data.
        uint8_t returnCount;
        if ((offset + readCount) <= size)
        {
            returnCount = readCount;
        }
        else
        {
            returnCount = size - offset;
        }

        std::vector<uint8_t> fruData((fruArea.begin() + offset),
                                     (fruArea.begin() + offset + returnCount));

        return ipmi::responseSuccess(returnCount, fruData);
    }
    catch (const InternalFailure& e)
    {
        lg2::error("Internal Failure: {ERROR}", "ERROR", e);
        return ipmi::responseUnspecifiedError();
    }
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

    // Get SDR count. This returns the total number of SDRs in the device.
    const auto& entityRecords =
        ipmi::sensor::EntityInfoMapContainer::getContainer()
            ->getIpmiEntityRecords();
    uint16_t records =
        ipmi::sensor::sensors.size() + frus.size() + entityRecords.size();

    return ipmi::responseSuccess(sdrVersion, records, freeSpace,
                                 additionTimestamp, deletionTimestamp,
                                 operationSupport);
}

void register_netfn_storage_functions()
{
    selCacheMapInitialized = false;
    initSELCache();
    // Handlers with dbus-sdr handler implementation.
    // Do not register the hander if it dynamic sensors stack is used.

#ifndef FEATURE_DYNAMIC_SENSORS

#ifndef FEATURE_DYNAMIC_STORAGES_ONLY
    // <Get SEL Info>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetSelInfo, ipmi::Privilege::User,
                          ipmiStorageGetSelInfo);

    // <Get SEL Timezone>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetSelTimeUtcOffset,
                          ipmi::Privilege::User,
                          ipmiStorageGetSelTimeUtcOffset);

    // <Get SEL Entry>
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_GET_SEL_ENTRY, NULL,
                           getSELEntry, PRIVILEGE_USER);

    // <Delete SEL Entry>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdDeleteSelEntry,
                          ipmi::Privilege::Operator, deleteSELEntry);

    // <Add SEL Entry>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdAddSelEntry,
                          ipmi::Privilege::Operator, ipmiStorageAddSEL);

    // <Clear SEL>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdClearSel, ipmi::Privilege::Operator,
                          clearSEL);

    // <Get FRU Inventory Area Info>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetFruInventoryAreaInfo,
                          ipmi::Privilege::User, ipmiStorageGetFruInvAreaInfo);

    // <READ FRU Data>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdReadFruData,
                          ipmi::Privilege::Operator, ipmiStorageReadFruData);

#endif // FEATURE_DYNAMIC_STORAGES_ONLY

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

#endif

    // Common Handers used by both implementation.

    // <Reserve SEL>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdReserveSel, ipmi::Privilege::User,
                          ipmiStorageReserveSel);

    // <Get SEL Time>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetSelTime, ipmi::Privilege::User,
                          ipmiStorageGetSelTime);

    // <Set SEL Time>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdSetSelTime,
                          ipmi::Privilege::Operator, ipmiStorageSetSelTime);

    ipmi::fru::registerCallbackHandler();
    return;
}
