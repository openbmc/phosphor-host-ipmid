#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/State/BMC/server.hpp>

#include <string>

static constexpr auto bmcStateRoot = "/xyz/openbmc_project/state";
static constexpr auto bmcStateIntf = "xyz.openbmc_project.State.BMC";
static constexpr auto reqTransition = "RequestedBMCTransition";
static constexpr auto match = "bmc0";

using BMC = sdbusplus::server::xyz::openbmc_project::state::BMC;

void register_netfn_global_functions() __attribute__((constructor));

/** @brief implements cold and warm reset commands
 *  @param - None
 *  @returns IPMI completion code.
 */
ipmi::RspType<> ipmiGlobalReset(ipmi::Context::ptr ctx)
{
    ipmi::DbusObjectInfo bmcStateObj;
    boost::system::error_code ec = ipmi::getDbusObject(
        ctx, bmcStateIntf, bmcStateRoot, match, bmcStateObj);
    if (!ec)
    {
        std::string service;
        ec = ipmi::getService(ctx, bmcStateIntf, bmcStateObj.first, service);
        if (!ec)
        {
            ec = ipmi::setDbusProperty(
                ctx, service, bmcStateObj.first, bmcStateIntf, reqTransition,
                convertForMessage(BMC::Transition::Reboot));
        }
    }
    if (ec)
    {
        lg2::error("Exception in Global Reset: {ERROR}", "ERROR", ec.message());
        return ipmi::responseUnspecifiedError();
    }

    // Status code.
    return ipmi::responseSuccess();
}

void register_netfn_global_functions()
{
    // Cold Reset
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdColdReset, ipmi::Privilege::Admin,
                          ipmiGlobalReset);
    return;
}
