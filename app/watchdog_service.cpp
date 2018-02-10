#include "watchdog_service.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/message.hpp>
#include <string>
#include <xyz/openbmc_project/State/Watchdog/server.hpp>

#include "ipmid.hpp"
#include "utils.hpp"

using sdbusplus::message::variant_ns::get;
using sdbusplus::message::variant_ns::variant;
using sdbusplus::xyz::openbmc_project::State::server;

static constexpr char *wd_path = "/xyz/openbmc_project/watchdog/host0";
static constexpr char *wd_intf = "xyz.openbmc_project.State.Watchdog";
static constexpr char *prop_intf = "org.freedesktop.DBus.Properties";

WatchdogService::WatchdogService()
    : bus(ipmid_get_sd_bus_connection()),
    wd_service(ipmi::getService(bus, wd_intf, wd_path))
{
}

WatchdogService::Properties WatchdogService::getProperties()
{
    auto request = bus.new_method_call(wd_service.c_str(), wd_path,
            prop_intf, "GetAll");
    request.append(wd_intf);
    auto response = bus.call(request);
    if (response.is_method_error())
    {
        throw std::runtime_error("Failed to get watchdog properties");
    }

    std::map<std::string, variant<bool, uint64_t, std::string>> properties;
    response.read(properties);
    Properties wd_prop;
    wd_prop.initialized = get<bool>(properties.at("Initialized"));
    wd_prop.enabled = get<bool>(properties.at("Enabled"));
    wd_prop.expireAction = server::Watchdog::convertActionFromString(
            get<std::string>(properties.at("ExpireAction")));
    wd_prop.interval = get<uint64_t>(properties.at("Interval"));
    wd_prop.timeRemaining = get<uint64_t>(properties.at("TimeRemaining"));
    return wd_prop;
}

template <typename T>
void WatchdogService::setProperty(const std::string& key, const T& val)
{
    auto request = bus.new_method_call(wd_service.c_str(), wd_path,
            prop_intf, "Set");
    request.append(wd_intf, key, variant<T>(val));
    auto response = bus.call(request);
    if (response.is_method_error())
    {
        throw std::runtime_error(std::string("Failed to set property: ") + key);
    }
}

void WatchdogService::setInitialized(bool initialized)
{
    setProperty("Initialized", initialized);
}

void WatchdogService::setEnabled(bool enabled)
{
    setProperty("Enabled", enabled);
}

void WatchdogService::setExpireAction(Action expireAction)
{
    setProperty("ExpireAction", server::convertForMessage(expireAction));
}

void WatchdogService::setInterval(uint64_t interval)
{
    setProperty("Interval", interval);
}

void WatchdogService::setTimeRemaining(uint64_t remaining)
{
    setProperty("TimeRemaining", remaining);
}
