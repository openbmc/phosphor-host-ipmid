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
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/message/types.hpp>
#include <sdbusplus/server.hpp>
#include <string>
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

/** @brief implements the get SEL Info command
 *  @returns IPMI completion code plus response data
 *   - selVersion - SEL revision
 *   - entries    - Number of log entries in SEL.
 *   - freeSpace  - Free Space in bytes.
 *   - addTimeStamp - Most recent addition timestamp
 *   - eraseTimeStamp - Most recent erase timestamp
 *   - operationSupport - Operation support.
 */

ipmi::RspType<uint8_t,  // SEL revision.
              uint16_t, // number of log entries in SEL.
              uint16_t, // free Space in bytes.
              uint32_t, // most recent addition timestamp
              uint32_t, // most recent erase timestamp.

              bool,    // SEL allocation info supported
              bool,    // reserve SEL supported
              bool,    // add SEL supported
              bool,    // delete SEL supported
              uint3_t, // reserved
              bool     // overflow flag
              >
    ipmiStorageGetSelInfo()
{
    uint8_t selVersion = ipmi::sel::selVersion;
    uint16_t entries = 0;
    uint16_t freeSpace;
    // Most recent addition timestamp.
    uint32_t addTimeStamp = ipmi::sel::invalidTimeStamp;
    uint32_t eraseTimeStamp = ipmi::sel::invalidTimeStamp;
    uint8_t operationSupport = ipmi::sel::operationSupport;
    bool selAllocInfoSuppFlag = static_cast<bool>(operationSupport & 0x01);
    bool ReserveSelSuppFlag = static_cast<bool>((operationSupport >> 1) & 0x01);
    bool addSelSupportFalg = static_cast<bool>((operationSupport >> 2) & 0x01);
    bool deleteSelSupportFlag =
        static_cast<bool>((operationSupport >> 3) & 0x01);
    constexpr uint3_t reserved{0};
    bool overflowFlag = static_cast<bool>((operationSupport >> 7) & 0x01);

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

    return ipmi::responseSuccess(selVersion, entries, freeSpace, addTimeStamp,
                                 eraseTimeStamp, selAllocInfoSuppFlag,
                                 ReserveSelSuppFlag, addSelSupportFalg,
                                 deleteSelSupportFlag, reserved, overflowFlag);
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
        host_time_usec = std::get<uint64_t>(value);
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

/** @brief implements the reserve SEL command
 *  @returns IPMI completion code plus response data
 *   - SEL reservation ID.
 */
ipmi::RspType<uint16_t> ipmiStorageReserveSel()
{
    return ipmi::responseSuccess(reserveSel());
}

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
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetSelInfo, ipmi::Privilege::User,
                          ipmiStorageGetSelInfo);

    // <Get SEL Time>
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_GET_SEL_TIME, NULL,
                           ipmi_storage_get_sel_time, PRIVILEGE_USER);

    // <Set SEL Time>
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_SET_SEL_TIME, NULL,
                           ipmi_storage_set_sel_time, PRIVILEGE_OPERATOR);

    // <Reserve SEL>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdReserveSel, ipmi::Privilege::User,
                          ipmiStorageReserveSel);
    // <Get SEL Entry>
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_GET_SEL_ENTRY, NULL,
                           getSELEntry, PRIVILEGE_USER);

    // <Delete SEL Entry>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdDeleteSelEntry,
                          ipmi::Privilege::Operator, deleteSELEntry);

    // <Add SEL Entry>
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_ADD_SEL, NULL,
                           ipmi_storage_add_sel, PRIVILEGE_OPERATOR);
    // <Clear SEL>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdClearSel, ipmi::Privilege::Operator,
                          clearSEL);

    // <Get FRU Inventory Area Info>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetFruInventoryAreaInfo,
                          ipmi::Privilege::User, ipmiStorageGetFruInvAreaInfo);

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
