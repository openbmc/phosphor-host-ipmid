#include "globalhandler.h"
#include "host-ipmid/ipmid-api.h"
#include "utils.hpp"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <mapper.h>

#include <sdbusplus/bus.hpp>
#include "xyz/openbmc_project/Common/error.hpp"

using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

constexpr auto control_object_name  =  "/org/openbmc/control/bmc0";
constexpr auto control_intf_name    =  "org.openbmc.control.Bmc";

void register_netfn_global_functions() __attribute__((constructor));

void dbus_reset(const char *method)
{
    std::string connection;

    try
    {
      sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
      connection = ipmi::getService(bus,
                                    control_intf_name,
                                    control_object_name);
    }
    catch (InternalFailure& e)
    {
        fprintf(stderr, "Failed to get connection for %s: %s\n",
                control_object_name, e.what());
        return;
    }

    printf("connection: %s\n", connection.c_str());

    // Open the system bus where most system services are provided.
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};

    /*
     * Bus, service, object path, interface and method are provided to call
     * the method.
     * Signatures and input arguments are provided by the arguments at the
     * end.
     */
    auto new_method = bus.new_method_call(
            connection.c_str(),             /* service to contact */
            control_object_name,            /* object path */
            control_intf_name,              /* interface name */
            method                          /* method name */
            );
    if (!bus.call(new_method))
    {
        fprintf(stderr, "Failed to issue method call: %s\n", method);
    }
}

ipmi_ret_t ipmi_global_warm_reset(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    printf("Handling GLOBAL warmReset Netfn:[0x%X], Cmd:[0x%X]\n",netfn, cmd);

    // TODO: call the correct dbus method for warmReset.
    dbus_reset("warmReset");

    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;
    return rc;
}

ipmi_ret_t ipmi_global_cold_reset(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    printf("Handling GLOBAL coldReset Netfn:[0x%X], Cmd:[0x%X]\n",netfn, cmd);

    // TODO: call the correct dbus method for coldReset.
    dbus_reset("coldReset");

    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;
    return rc;
}

void register_netfn_global_functions()
{
    // Cold Reset
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_COLD_RESET);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_COLD_RESET, NULL, ipmi_global_cold_reset,
                           PRIVILEGE_ADMIN);

    // <Warm Reset>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_WARM_RESET);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_WARM_RESET, NULL, ipmi_global_warm_reset,
                           PRIVILEGE_ADMIN);

    return;
}
