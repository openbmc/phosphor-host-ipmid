#include "host-ipmid/ipmid-api.h"
#include "storageaddsel.h"
#include "storagehandler.h"
#include "utils.hpp"

#include <phosphor-logging/log.hpp>

#include <arpa/inet.h>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <mapper.h>
#include <string>
#include <systemd/sd-bus.h>

using namespace phosphor::logging;
using namespace std::chrono;

void register_netfn_storage_functions() __attribute__((constructor));


extern unsigned short g_sel_reserve;

namespace {
constexpr auto TIME_INTERFACE = "xyz.openbmc_project.Time.EpochTime";
constexpr auto HOST_TIME_PATH = "/xyz/openbmc_project/time/host";
constexpr auto DBUS_PROPERTIES = "org.freedesktop.DBus.Properties";
constexpr auto PROPERTY_ELAPSED= "Elapsed";

const char* getTimeString(const uint64_t& usecSinceEpoch)
{
    system_clock::time_point tp{microseconds(usecSinceEpoch)};
    auto t = system_clock::to_time_t(tp);
    return std::ctime(&t);
}
}

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
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    std::string service;
    uint64_t host_time_usec = 0;
    uint32_t resp = 0;

    printf("IPMI Handling GET-SEL-TIME\n");

    try
    {
        service = ipmi::getService(bus, TIME_INTERFACE, HOST_TIME_PATH);
        sdbusplus::message::variant<uint64_t> value;

        // Get host time
        auto method = bus.new_method_call(service.c_str(),
                                          HOST_TIME_PATH,
                                          DBUS_PROPERTIES,
                                          "Get");

        method.append(TIME_INTERFACE, PROPERTY_ELAPSED);
        auto reply = bus.call(method);
        if (reply.is_method_error())
        {
            log<level::ERR>("Error getting time");
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
        reply.read(value);
        host_time_usec = value.get<uint64_t>();
    }
    catch (const std::runtime_error& e)
    {
        log<level::ERR>(e.what());
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    printf("Host time: %" PRIu64 ", %s",
           host_time_usec, getTimeString(host_time_usec));

    // Time is really long int but IPMI wants just uint32. This works okay until
    // the number of seconds since 1970 overflows uint32 size.. Still a whole
    // lot of time here to even think about that.
    resp = duration_cast<seconds>(microseconds(host_time_usec)).count();
    resp = htole32(resp);

    // From the IPMI Spec 2.0, response should be a 32-bit value
    *data_len = sizeof(resp);

    // Pack the actual response
    memcpy(response, &resp, *data_len);

    return IPMI_CC_OK;
}

ipmi_ret_t ipmi_storage_set_sel_time(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    std::string service;
    ipmi_ret_t rc = IPMI_CC_OK;
    uint32_t secs = *(uint32_t*)request;
    *data_len = 0;

    printf("Handling Set-SEL-Time:[0x%X], Cmd:[0x%X], Data:[0x%X]\n",
           netfn, cmd, secs);

    secs = le32toh(secs);
    microseconds usec{seconds(secs)};

    printf("To Set host time: %" PRIu64 ", %s",
           usec.count(), getTimeString(usec.count()));

    try
    {
        service = ipmi::getService(bus, TIME_INTERFACE, HOST_TIME_PATH);
        sdbusplus::message::variant<uint64_t> value{usec.count()};

        // Get host time
        auto method = bus.new_method_call(service.c_str(),
                                          HOST_TIME_PATH,
                                          DBUS_PROPERTIES,
                                          "Set");

        method.append(TIME_INTERFACE, PROPERTY_ELAPSED, value);
        auto reply = bus.call(method);
        if (reply.is_method_error())
        {
            log<level::ERR>("Error setting time");
            rc = IPMI_CC_UNSPECIFIED_ERROR;
        }
    }
    catch (const std::runtime_error& e)
    {
        log<level::ERR>(e.what());
        rc = IPMI_CC_UNSPECIFIED_ERROR;
    }

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
    return;
}

