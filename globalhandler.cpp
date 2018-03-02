#include "globalhandler.h"
#include "host-ipmid/ipmid-api.h"
#include <stdio.h>
#include <string>
#include <utils.hpp>

static constexpr auto bmcStateObj = "/xyz/openbmc_project/state/bmc0";
static constexpr auto bmcStateIntf =
    "xyz.openbmc_project.State.BMC";
static constexpr auto reqTransition = "RequestedBMCTransition";
static constexpr auto reboot =
    "xyz.openbmc_project.State.BMC.Transition.Reboot";




void register_netfn_global_functions() __attribute__((constructor));

void setBMCTransition(std::string value)
{
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};

    auto service = ipmi::getService(bus, bmcStateIntf, bmcStateObj);
    ipmi::setDbusProperty(bus, service, bmcStateObj, bmcStateIntf,
                          reqTransition, value);
}

ipmi_ret_t ipmi_global_warm_reset(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                  ipmi_request_t request,
                                  ipmi_response_t response,
                                  ipmi_data_len_t data_len,
                                  ipmi_context_t context)
{
    printf("Handling GLOBAL warmReset Netfn:[0x%X], Cmd:[0x%X]\n", netfn, cmd);

    setBMCTransition(reboot);

    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;
    return rc;
}

ipmi_ret_t ipmi_global_cold_reset(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                  ipmi_request_t request,
                                  ipmi_response_t response,
                                  ipmi_data_len_t data_len,
                                  ipmi_context_t context)
{
    printf("Handling GLOBAL coldReset Netfn:[0x%X], Cmd:[0x%X]\n", netfn, cmd);

    setBMCTransition(reboot);

    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;
    return rc;
}

void register_netfn_global_functions()
{
    // Cold Reset
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n", NETFUN_APP,
           IPMI_CMD_COLD_RESET);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_COLD_RESET, NULL,
                           ipmi_global_cold_reset,
                           PRIVILEGE_ADMIN);

    // <Warm Reset>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n", NETFUN_APP,
           IPMI_CMD_WARM_RESET);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_WARM_RESET, NULL,
                           ipmi_global_warm_reset,
                           PRIVILEGE_ADMIN);

    return;
}
