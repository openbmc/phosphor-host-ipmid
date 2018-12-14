#include "globalhandler.hpp"

#include "utils.hpp"

#include <ipmid/api.h>

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <string>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/State/BMC/server.hpp>

static constexpr auto bmcStateRoot = "/xyz/openbmc_project/state";
static constexpr auto bmcStateIntf = "xyz.openbmc_project.State.BMC";
static constexpr auto reqTransition = "RequestedBMCTransition";
static constexpr auto match = "bmc0";

using namespace phosphor::logging;
using BMC = sdbusplus::xyz::openbmc_project::State::server::BMC;

void register_netfn_global_functions() __attribute__((constructor));

void resetBMC()
{
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};

    auto bmcStateObj =
        ipmi::getDbusObject(bus, bmcStateIntf, bmcStateRoot, match);

    auto service = ipmi::getService(bus, bmcStateIntf, bmcStateObj.first);

    ipmi::setDbusProperty(bus, service, bmcStateObj.first, bmcStateIntf,
                          reqTransition,
                          convertForMessage(BMC::Transition::Reboot));
}

ipmi_ret_t ipmi_global_reset(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    try
    {
        resetBMC();
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
                           ipmi_global_reset, PRIVILEGE_ADMIN);

    // <Warm Reset>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_WARM_RESET, NULL,
                           ipmi_global_reset, PRIVILEGE_ADMIN);

    return;
}
