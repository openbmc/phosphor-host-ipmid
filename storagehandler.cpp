#include <cstdio>
#include <string>
#include <arpa/inet.h>
#include <systemd/sd-bus.h>
#include <mapper.h>
#include <chrono>
#include "selutility.hpp"
#include "storagehandler.h"
#include "storageaddsel.h"
#include "host-ipmid/ipmid-api.h"
#include <experimental/filesystem>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/server.hpp>
#include "xyz/openbmc_project/Common/error.hpp"

void register_netfn_storage_functions() __attribute__((constructor));


unsigned int   g_sel_time    = 0xFFFFFFFF;
extern unsigned short g_sel_reserve;

constexpr auto time_manager_intf = "org.openbmc.TimeManager";
constexpr auto time_manager_obj = "/org/openbmc/TimeManager";

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

} // namespace objectPathsCache

using InternalFailure =
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
using namespace phosphor::logging;

ipmi_ret_t ipmi_storage_wildcard(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    printf("Handling STORAGE WILDCARD Netfn:[0x%X], Cmd:[0x%X]\n",netfn, cmd);
    // Status code.
    ipmi_ret_t rc = IPMI_CC_INVALID;
    *data_len = 0;
    return rc;
}

ipmi_ret_t getSELInfo(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                      ipmi_request_t request, ipmi_response_t response,
                      ipmi_data_len_t data_len, ipmi_context_t context)
{
    std::vector<uint8_t> outPayload(sizeof(ipmi::sel::GetSELInfoResponse));
    auto responseData = reinterpret_cast<ipmi::sel::GetSELInfoResponse*>
            (outPayload.data());

    responseData->selVersion = ipmi::sel::selVersion;
    // Last erase timestamp is not available from log manager.
    responseData->eraseTimeStamp = ipmi::sel::invalidTimeStamp;
    responseData->operationSupport = ipmi::sel::operationSupport;

    ipmi::sel::readLoggingObjectPaths(cache::paths);

    if (cache::paths.empty())
    {
        responseData->entries = 0;
        responseData->addTimeStamp = ipmi::sel::invalidTimeStamp;
    }
    else
    {
        responseData->entries = static_cast<uint16_t>(cache::paths.size());

        try
        {
            responseData->addTimeStamp = ipmi::sel::getEntryTimeStamp(
                    cache::paths.back());
        }
        catch (InternalFailure& e)
        {
            responseData->addTimeStamp = ipmi::sel::invalidTimeStamp;
        }
        catch (const std::runtime_error& e)
        {
            log<level::ERR>(e.what());
            responseData->addTimeStamp = ipmi::sel::invalidTimeStamp;
        }
    }

    memcpy(response, outPayload.data(), outPayload.size());
    *data_len = outPayload.size();

    return IPMI_CC_OK;
}

ipmi_ret_t getSELEntry(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                       ipmi_request_t request, ipmi_response_t response,
                       ipmi_data_len_t data_len, ipmi_context_t context)
{
    auto requestData = reinterpret_cast<const ipmi::sel::GetSELEntryRequest*>
                   (request);

    if (requestData->reservationID != 0)
    {
        if (g_sel_reserve != requestData->reservationID)
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

    ipmi::sel::GetSELEntryResponse record {};

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
    if(iter != cache::paths.end())
    {
        ++iter;
        if (iter == cache::paths.end())
        {
            record.nextRecordID = ipmi::sel::lastEntry;
        }
        else
        {
            namespace fs = std::experimental::filesystem;
            fs::path path(*iter);
            record.nextRecordID = static_cast<uint16_t>
                     (std::stoul(std::string(path.filename().c_str())));
        }
    }
    else
    {
        record.nextRecordID = ipmi::sel::lastEntry;
    }

    if (requestData->readLength == ipmi::sel::entireRecord)
    {
        memcpy(response, &record, sizeof(record));
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
        auto readLength = std::min(diff,
                                   static_cast<int>(requestData->readLength));

        memcpy(response, &record.nextRecordID, sizeof(record.nextRecordID));
        memcpy(static_cast<uint8_t*>(response) + sizeof(record.nextRecordID),
               &record.recordID + requestData->offset, readLength);
        *data_len = sizeof(record.nextRecordID) + readLength;
    }

    return IPMI_CC_OK;
}

ipmi_ret_t ipmi_storage_get_sel_time(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    using namespace std::chrono;

    char *time_provider = nullptr;
    const char* time_in_str = nullptr;
    uint64_t host_time_usec = 0;
    uint32_t resp = 0;
    ipmi_ret_t rc = IPMI_CC_OK;

    sd_bus_message *reply = nullptr;
    sd_bus_error bus_error = SD_BUS_ERROR_NULL;

    printf("IPMI Handling GET-SEL-TIME\n");

    auto bus = ipmid_get_sd_bus_connection();

    auto rct = mapper_get_service(bus, time_manager_obj, &time_provider);
    if (rct < 0) {
        printf("Error [%s] getting bus name for time provider\n",
            strerror(-rct));
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        goto finish;
    }

    rct = sd_bus_call_method(bus,
                    time_provider,
                    time_manager_obj,
                    time_manager_intf,
                    "GetTime",
                    &bus_error,
                    &reply,
                    "s",
                    "host");
    if (rct < 0) {
        printf("Error [%s] getting time\n", strerror(-rct));
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        goto finish;
    }

    rct = sd_bus_message_read(reply, "sx", &time_in_str, &host_time_usec);
    if (rct < 0) {
        fprintf(stderr, "Error [%s] parsing get-time response\n",
                strerror(-rct));
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        goto finish;
    }

    // Time is really long int but IPMI wants just uint32. This works okay until
    // the number of seconds since 1970 overflows uint32 size.. Still a whole
    // lot of time here to even think about that.
    resp = duration_cast<seconds>(microseconds(host_time_usec)).count();
    resp = htole32(resp);
    printf("Host Time read:[%s] :: [%d]\n", time_in_str, resp);

    // From the IPMI Spec 2.0, response should be a 32-bit value
    *data_len = sizeof(resp);

    // Pack the actual response
    memcpy(response, &resp, *data_len);

finish:
    sd_bus_error_free(&bus_error);
    reply = sd_bus_message_unref(reply);
    free(time_provider);
    return rc;
}

ipmi_ret_t ipmi_storage_set_sel_time(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    char *time_provider = nullptr;
    int time_rc = 0;
    ipmi_ret_t rc = IPMI_CC_OK;

    sd_bus_message *reply = nullptr;
    sd_bus_error bus_error = SD_BUS_ERROR_NULL;

    uint32_t* secs = (uint32_t*)request;
    *data_len = 0;

    printf("Handling Set-SEL-Time:[0x%X], Cmd:[0x%X]\n",netfn, cmd);
    printf("Data: 0x%X]\n",*secs);

    auto bus = ipmid_get_sd_bus_connection();

    auto rct = mapper_get_service(bus, time_manager_obj, &time_provider);
    if (rct < 0) {
        printf("Error [%s] getting bus name for time provider\n",
            strerror(-rct));
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        goto finish;
    }

    rct = sd_bus_call_method(bus,
            time_provider,
            time_manager_obj,
            time_manager_intf,
            "SetTime",
            &bus_error,
            &reply,
            "ss",
            "host",
            std::to_string(le32toh(*secs)).c_str());

    if (rct < 0) {
        printf("Error [%s] setting time\n", strerror(-rct));
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        goto finish;
    }

    rct = sd_bus_message_read(reply, "i", &time_rc);
    if (rct < 0) {
        fprintf(stderr, "Error [%s] parsing set-time response\n",
                strerror(-rct));
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        goto finish;
    }

    if (time_rc < 0) {
        printf("Error setting time.");
        rc = IPMI_CC_UNSPECIFIED_ERROR;
    }

finish:
    sd_bus_error_free(&bus_error);
    reply = sd_bus_message_unref(reply);
    free(time_provider);
    return rc;
}

ipmi_ret_t ipmi_storage_reserve_sel(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;

    // IPMI spec, Reservation ID, the value simply increases against each execution of reserve_sel command.
    if( ++g_sel_reserve == 0)
        g_sel_reserve = 1;

    printf("IPMI Handling RESERVE-SEL 0x%04x\n", g_sel_reserve);

    *data_len = sizeof(g_sel_reserve);

    // Pack the actual response
    memcpy(response, &g_sel_reserve, *data_len);

    return rc;
}

ipmi_ret_t ipmi_storage_add_sel(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{

    ipmi_ret_t rc = IPMI_CC_OK;
    ipmi_add_sel_request_t *p = (ipmi_add_sel_request_t*) request;
    uint16_t recordid;

    recordid = ((uint16_t)p->eventdata[1] << 8) | p->eventdata[2];

    printf("IPMI Handling ADD-SEL for record 0x%04x\n", recordid);

    *data_len = sizeof(g_sel_reserve);

    // Pack the actual response
    memcpy(response, &p->eventdata[1], 2);

    send_esel(recordid);

    return rc;
}



void register_netfn_storage_functions()
{
    // <Wildcard Command>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_WILDCARD);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_WILDCARD, NULL, ipmi_storage_wildcard,
                           PRIVILEGE_USER);

    // <Get SEL Info>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_GET_SEL_INFO);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_GET_SEL_INFO, NULL, getSELInfo,
                           PRIVILEGE_USER);

    // <Get SEL Time>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_GET_SEL_TIME);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_GET_SEL_TIME, NULL, ipmi_storage_get_sel_time,
                           PRIVILEGE_USER);

    // <Set SEL Time>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_SET_SEL_TIME);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_SET_SEL_TIME, NULL, ipmi_storage_set_sel_time,
                           PRIVILEGE_OPERATOR);

    // <Reserve SEL>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_RESERVE_SEL);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_RESERVE_SEL, NULL, ipmi_storage_reserve_sel,
                           PRIVILEGE_USER);

    // <Get SEL Entry>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_GET_SEL_ENTRY);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_GET_SEL_ENTRY, NULL, getSELEntry,
                           PRIVILEGE_USER);

    // <Add SEL Entry>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_ADD_SEL);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_ADD_SEL, NULL, ipmi_storage_add_sel,
                           PRIVILEGE_OPERATOR);
    return;
}

