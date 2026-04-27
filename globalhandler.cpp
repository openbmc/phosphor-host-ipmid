#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/State/BMC/server.hpp>

#include <atomic>
#include <chrono>
#include <string>
#include <thread>

static std::atomic_flag resetQueued = ATOMIC_FLAG_INIT;

static constexpr auto systemdService = "org.freedesktop.systemd1";
static constexpr auto systemdObjPath = "/org/freedesktop/systemd1";
static constexpr auto systemdInterface = "org.freedesktop.systemd1.Manager";
static constexpr auto warmResetTarget = "phosphor-ipmi-warm-reset.target";

using BMCState = sdbusplus::server::xyz::openbmc_project::state::BMC;

void registerNetFnGlobalFunctions() __attribute__((constructor));

/** @brief implements cold and warm reset commands
 *  @param - None
 *  @returns IPMI completion code.
 */
ipmi::RspType<> ipmiGlobalReset(ipmi::Context::ptr ctx)
{
    ipmi::DbusObjectInfo bmcStateObj;
    boost::system::error_code ec = ipmi::getDbusObject(
        ctx, BMCState::interface, BMCState::namespace_path::value,
        BMCState::namespace_path::bmc, bmcStateObj);
    if (!ec)
    {
        std::string service;
        ec = ipmi::getService(ctx, BMCState::interface, bmcStateObj.first,
                              service);
        if (!ec)
        {
            ec = ipmi::setDbusProperty(
                ctx, service, bmcStateObj.first, BMCState::interface,
                BMCState::property_names::requested_bmc_transition,
                convertForMessage(BMCState::Transition::Reboot));
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

static void warmResetBMC()
{
    try
    {
        std::shared_ptr<sdbusplus::asio::connection> busp = getSdBus();
        // Reset the failed units so systemd properly restarts
        // if the command is sent repeatedly.
        busp->async_method_call(
            [](boost::system::error_code ec) {
                if (ec)
                {
                    lg2::error("Error in warm reset ResetFailed: {ERROR}",
                               "ERROR", ec.message());
                }
            },
            systemdService, systemdObjPath, systemdInterface, "ResetFailed");
        // Restart the target (restart will propagate to units).
        busp->async_method_call(
            [](boost::system::error_code ec) {
                if (ec)
                {
                    lg2::error("Error in warm reset RestartUnit: {ERROR}",
                               "ERROR", ec.message());
                }
            },
            systemdService, systemdObjPath, systemdInterface, "RestartUnit",
            warmResetTarget, "replace");
    }
    catch (const std::exception& e)
    {
        lg2::error("Exception in warmResetBMC: {ERROR}", "ERROR", e);
    }
}

/** @brief implements warm reset command
 *  @param - None
 *  @returns IPMI completion code.
 */
ipmi::RspType<> ipmiWarmReset()
{
    try
    {
        if (resetQueued.test_and_set())
        {
            return ipmi::responseCommandNotAvailable();
        }
        std::thread([]() {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            try
            {
                warmResetBMC();
                resetQueued.clear();
            }
            catch (const std::exception& ex)
            {
                lg2::error("Exception in warm reset thread: {ERROR}", "ERROR",
                           ex);
                resetQueued.clear();
            }
        }).detach();
    }
    catch (const std::exception& e)
    {
        lg2::error("Exception scheduling warm reset: {ERROR}", "ERROR", e);
        resetQueued.clear();
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess();
}

void registerNetFnGlobalFunctions()
{
    // Cold Reset
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdColdReset, ipmi::Privilege::Admin,
                          ipmiGlobalReset);

    // Warm Reset
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdWarmReset, ipmi::Privilege::Admin,
                          ipmiWarmReset);
    return;
}
