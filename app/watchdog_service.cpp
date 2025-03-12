#include "watchdog_service.hpp"

#include <ipmid/api.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/message.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/State/Watchdog/server.hpp>

#include <exception>
#include <stdexcept>
#include <string>

using phosphor::logging::elog;
using phosphor::logging::entry;
using phosphor::logging::level;
using phosphor::logging::log;
using sdbusplus::common::xyz::openbmc_project::state::convertForMessage;
using sdbusplus::error::xyz::openbmc_project::common::InternalFailure;
using sdbusplus::server::xyz::openbmc_project::state::Watchdog;

static constexpr auto wdPath = "/xyz/openbmc_project/watchdog/host0";
static constexpr auto wdIntf = "xyz.openbmc_project.State.Watchdog";
static constexpr auto propIntf = "org.freedesktop.DBus.Properties";

ipmi::ServiceCache WatchdogService::wdService(wdIntf, wdPath);

WatchdogService::WatchdogService() : bus(ipmid_get_sd_bus_connection()) {}

void WatchdogService::resetTimeRemaining(bool enableWatchdog)
{
    bool wasValid = wdService.isValid(bus);
    auto request = wdService.newMethodCall(bus, wdIntf, "ResetTimeRemaining");
    request.append(enableWatchdog);
    try
    {
        auto response = bus.call(request);
    }
    catch (const std::exception& e)
    {
        wdService.invalidate();
        if (wasValid)
        {
            // Retry the request once in case the cached service was stale
            return resetTimeRemaining(enableWatchdog);
        }
        lg2::error("WatchdogService: Method error resetting time remaining, "
                   "ENABLE_WATCHDOG: {ENABLE_WATCHDOG}, ERROR: {ERROR}",
                   "ENABLE_WATCHDOG", enableWatchdog, "ERROR", e);
        elog<InternalFailure>();
    }
}

WatchdogService::Properties WatchdogService::getProperties()
{
    bool wasValid = wdService.isValid(bus);
    auto request = wdService.newMethodCall(bus, propIntf, "GetAll");
    request.append(wdIntf);

    std::map<std::string, std::variant<bool, uint64_t, std::string>> properties;
    try
    {
        auto response = bus.call(request);
        response.read(properties);
    }
    catch (const std::exception& e)
    {
        wdService.invalidate();
        if (wasValid)
        {
            // Retry the request once in case the cached service was stale
            return getProperties();
        }
        lg2::error("WatchdogService: Method error getting properties: {ERROR}",
                   "ERROR", e);
        elog<InternalFailure>();
    }

    try
    {
        Properties wdProp;
        wdProp.initialized = std::get<bool>(properties.at("Initialized"));
        wdProp.enabled = std::get<bool>(properties.at("Enabled"));
        wdProp.expireAction = Watchdog::convertActionFromString(
            std::get<std::string>(properties.at("ExpireAction")));
        wdProp.timerUse = Watchdog::convertTimerUseFromString(
            std::get<std::string>(properties.at("CurrentTimerUse")));
        wdProp.expiredTimerUse = Watchdog::convertTimerUseFromString(
            std::get<std::string>(properties.at("ExpiredTimerUse")));

        wdProp.interval = std::get<uint64_t>(properties.at("Interval"));
        wdProp.timeRemaining =
            std::get<uint64_t>(properties.at("TimeRemaining"));
        return wdProp;
    }
    catch (const std::exception& e)
    {
        lg2::error("WatchdogService: Decode error in get properties: {ERROR}",
                   "ERROR", e);
        elog<InternalFailure>();
    }

    // Needed instead of elog<InternalFailure>() since the compiler can't
    // deduce the that elog<>() always throws
    throw std::runtime_error(
        "WatchdogService: Should not reach end of getProperties");
}

template <typename T>
T WatchdogService::getProperty(const std::string& key)
{
    bool wasValid = wdService.isValid(bus);
    auto request = wdService.newMethodCall(bus, propIntf, "Get");
    request.append(wdIntf, key);
    try
    {
        auto response = bus.call(request);
        std::variant<T> value;
        response.read(value);
        return std::get<T>(value);
    }
    catch (const std::exception& e)
    {
        wdService.invalidate();
        if (wasValid)
        {
            // Retry the request once in case the cached service was stale
            return getProperty<T>(key);
        }
        lg2::error("WatchdogService: Method error getting {PROPERTY}: {ERROR}",
                   "PROPERTY", key, "ERROR", e);
        elog<InternalFailure>();
    }

    // Needed instead of elog<InternalFailure>() since the compiler can't
    // deduce the that elog<>() always throws
    throw std::runtime_error(
        "WatchdogService: Should not reach end of getProperty");
}

template <typename T>
void WatchdogService::setProperty(const std::string& key, const T& val)
{
    bool wasValid = wdService.isValid(bus);
    auto request = wdService.newMethodCall(bus, propIntf, "Set");
    request.append(wdIntf, key, std::variant<T>(val));
    try
    {
        auto response = bus.call(request);
    }
    catch (const std::exception& e)
    {
        wdService.invalidate();
        if (wasValid)
        {
            // Retry the request once in case the cached service was stale
            setProperty(key, val);
            return;
        }
        lg2::error("WatchdogService: Method error setting {PROPERTY}: {ERROR}",
                   "PROPERTY", key, "ERROR", e);
        elog<InternalFailure>();
    }
}

bool WatchdogService::getInitialized()
{
    return getProperty<bool>("Initialized");
}

void WatchdogService::setInitialized(bool initialized)
{
    setProperty("Initialized", initialized);
}

void WatchdogService::setEnabled(bool enabled)
{
    setProperty("Enabled", enabled);
}

void WatchdogService::setLogTimeout(bool LogTimeout)
{
    setProperty("LogTimeout", LogTimeout);
}

void WatchdogService::setExpireAction(Action expireAction)
{
    setProperty("ExpireAction", convertForMessage(expireAction));
}

void WatchdogService::setTimerUse(TimerUse timerUse)
{
    setProperty("CurrentTimerUse", convertForMessage(timerUse));
}

void WatchdogService::setExpiredTimerUse(TimerUse timerUse)
{
    setProperty("ExpiredTimerUse", convertForMessage(timerUse));
}

void WatchdogService::setInterval(uint64_t interval)
{
    setProperty("Interval", interval);
}
