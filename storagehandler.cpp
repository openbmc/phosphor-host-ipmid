#include <cstdio>
#include <string>
#include <arpa/inet.h>
#include <systemd/sd-bus.h>
#include <mapper.h>
#include <chrono>
#include <algorithm>
#include "storagehandler.h"
#include "storageaddsel.h"
#include "host-ipmid/ipmid-api.h"
#include "read_fru_data.hpp"
#include "xyz/openbmc_project/Common/error.hpp"
#include <phosphor-logging/elog-errors.hpp>

void register_netfn_storage_functions() __attribute__((constructor));

unsigned int   g_sel_time    = 0xFFFFFFFF;
extern unsigned short g_sel_reserve;

constexpr auto time_manager_intf = "org.openbmc.TimeManager";
constexpr auto time_manager_obj = "/org/openbmc/TimeManager";

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

using InternalFailure =
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

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

ipmi_ret_t ipmi_storage_get_sel_info(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{

    ipmi_ret_t rc = IPMI_CC_OK;
    unsigned char buf[] = {0x51,0,0,0xff, 0xff,0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,0x06};

    printf("IPMI Handling GET-SEL-INFO\n");

    *data_len = sizeof(buf);

    // TODO There is plently of work here.  The SEL DB needs to hold a bunch
    // of things in a header.  Items like Time Stamp, number of entries, etc
    // This is one place where the dbus object with the SEL information could
    // mimic what IPMI needs.

    // Pack the actual response
    memcpy(response, &buf, *data_len);

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

//Read FRU info area
ipmi_ret_t ipmi_storage_get_fru_inv_area_info(
        ipmi_netfn_t netfn, ipmi_cmd_t cmd, ipmi_request_t request,
        ipmi_response_t response, ipmi_data_len_t data_len,
        ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    FruInvenAreaInfoRequest* reqptr =
        reinterpret_cast<FruInvenAreaInfoRequest*>(request);
    try
    {
        auto& fruArea = getFruAreaData(reqptr->fruID);
        auto size = static_cast<uint16_t>(fruArea.size());
        FruInvenAreaInfoResponse resp;
        resp.sizems = size >> 8;
        resp.sizels = size;
        resp.access = static_cast<uint8_t>(AccessMode::bytes);

        *data_len = sizeof(resp);

        // Pack the actual response
        memcpy(response, &resp, *data_len);
    }
    catch(InternalFailure& e)
    {
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        log<level::ERR>(e.what());
        report<InternalFailure>();
    }
    return rc;
}

//Read FRU data
ipmi_ret_t ipmi_storage_read_fru_data(
        ipmi_netfn_t netfn, ipmi_cmd_t cmd, ipmi_request_t request,
        ipmi_response_t response, ipmi_data_len_t data_len,
        ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    ReadFruDataRequest* reqptr =
        reinterpret_cast<ReadFruDataRequest*>(request);
    uint16_t offset = 
        (static_cast<uint16_t>(reqptr->offsetMS)) << 8 | reqptr->offsetLS;
    try
    {
        auto& fruArea = getFruAreaData(reqptr->fruID);
        auto size = fruArea.size();
        if ((offset + reqptr->count) > size)
        {
            log<level::ERR>("Invalid offset and count",
                entry("Offset=%d Count=%d SizeOfFruArea=%d",
                offset, reqptr->count, size));
            return IPMI_CC_INVALID;
        }
        std::copy((fruArea.begin() + offset), (fruArea.begin()+reqptr->count),
                (static_cast<uint8_t*>(response)));
        *data_len = reqptr->count;
    }
    catch (InternalFailure& e)
    {
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        log<level::ERR>(e.what());
        report<InternalFailure>();
    }
    return rc;
}


void register_netfn_storage_functions()
{
    // <Wildcard Command>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_WILDCARD);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_WILDCARD, NULL, ipmi_storage_wildcard,
                           PRIVILEGE_USER);

    // <Get SEL Time>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_GET_SEL_TIME);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_GET_SEL_TIME, NULL, ipmi_storage_get_sel_time,
                           PRIVILEGE_USER);

    // <Set SEL Time>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_SET_SEL_TIME);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_SET_SEL_TIME, NULL, ipmi_storage_set_sel_time,
                           PRIVILEGE_OPERATOR);

    // <Get SEL Info>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_GET_SEL_INFO);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_GET_SEL_INFO, NULL, ipmi_storage_get_sel_info,
                           PRIVILEGE_USER);

    // <Reserve SEL>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_RESERVE_SEL);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_RESERVE_SEL, NULL, ipmi_storage_reserve_sel,
                           PRIVILEGE_USER);

    // <Add SEL Entry>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_ADD_SEL);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_ADD_SEL, NULL, ipmi_storage_add_sel,
                           PRIVILEGE_OPERATOR);
    // <Get FRU Inventory Area Info>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n", NETFUN_STORAGE,
            IPMI_CMD_GET_FRU_INV_AREA_INFO);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_GET_FRU_INV_AREA_INFO, NULL,
            ipmi_storage_get_fru_inv_area_info, PRIVILEGE_OPERATOR);

    // <Add READ FRU Data
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n", NETFUN_STORAGE,
            IPMI_CMD_READ_FRU_DATA);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_READ_FRU_DATA, NULL,
            ipmi_storage_read_fru_data, PRIVILEGE_OPERATOR);

    return;
}

