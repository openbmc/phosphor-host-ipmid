#include "globalhandler.h"
#include "host-ipmid/ipmid-api.h"
#include <stdio.h>
#include <string>
#include <utils.hpp>
#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include "xyz/openbmc_project/Common/error.hpp"

static constexpr auto bmcStateObj = "/xyz/openbmc_project/state/bmc0";
static constexpr auto bmcStateIntf =
    "xyz.openbmc_project.State.BMC";
static constexpr auto reqTransition = "RequestedBMCTransition";
static constexpr auto bmcReboot =
    "xyz.openbmc_project.State.BMC.Transition.Reboot";


using namespace phosphor::logging;

void register_netfn_global_functions() __attribute__((constructor));

void setBMCTransition()
{
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};

    auto service = ipmi::getService(bus, bmcStateIntf, bmcStateObj);
    ipmi::setDbusProperty(bus, service, bmcStateObj, bmcStateIntf,
                          reqTransition, std::string(bmcReboot));
}

ipmi_ret_t ipmi_global_warm_reset(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                  ipmi_request_t request,
                                  ipmi_response_t response,
                                  ipmi_data_len_t data_len,
                                  ipmi_context_t context)
{
    try
    {
    setBMCTransition();
    }
    catch (std::exception& e)
    {
        log<level::ERR>(e.what());
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

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
    try
    {
    setBMCTransition();
    }
    catch (std::exception& e)
    {
        log<level::ERR>(e.what());
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;
    return rc;
}

void register_netfn_global_functions()
{
    // Cold Reset
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_COLD_RESET, NULL,
                           ipmi_global_cold_reset,
                           PRIVILEGE_ADMIN);

    // <Warm Reset>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_WARM_RESET, NULL,
                           ipmi_global_warm_reset,
                           PRIVILEGE_ADMIN);

    return;
}
