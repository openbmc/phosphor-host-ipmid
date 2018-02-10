#include "watchdog.hpp"

#include <cstdint>
#include <endian.h>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/message.hpp>
#include <string>
#include <xyz/openbmc_project/State/Watchdog/server.hpp>

#include "host-ipmid/ipmid-api.h"
#include "ipmid.hpp"
#include "utils.hpp"

using sdbusplus::message::variant_ns::get;
using sdbusplus::message::variant_ns::variant;
using sdbusplus::xyz::openbmc_project::State::server::convertForMessage;
using sdbusplus::xyz::openbmc_project::State::server::Watchdog;
using phosphor::logging::level;
using phosphor::logging::log;

struct WatchdogProperties {
    bool initialized;
    bool enabled;
    Watchdog::Action expireAction;
    uint64_t interval;
    uint64_t timeRemaining;
};

class WatchdogService {
    public:
        WatchdogService();
        WatchdogProperties getProperties();
        void setInitialized(bool initialized);
        void setEnabled(bool enabled);
        void setExpireAction(Watchdog::Action expireAction);
        void setInterval(uint64_t interval);
        void setTimeRemaining(uint64_t remaining);

    private:
        static constexpr auto wd_path = "/xyz/openbmc_project/watchdog/host0";
        static constexpr auto wd_intf = "xyz.openbmc_project.State.Watchdog";
        static constexpr auto prop_intf = "org.freedesktop.DBus.Properties";

        sdbusplus::bus::bus bus;
        const std::string wd_service;

        template <typename T>
        void setProperty(const std::string& key, const T& val);
};

WatchdogService::WatchdogService()
    : bus(ipmid_get_sd_bus_connection()),
    wd_service(ipmi::getService(bus, wd_intf, wd_path))
{
}

WatchdogProperties WatchdogService::getProperties()
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
    WatchdogProperties wd_prop;
    wd_prop.initialized = get<bool>(properties.at("Initialized"));
    wd_prop.enabled = get<bool>(properties.at("Enabled"));
    wd_prop.expireAction = Watchdog::convertActionFromString(
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

void WatchdogService::setExpireAction(Watchdog::Action expireAction)
{
    setProperty("ExpireAction", convertForMessage(expireAction));
}

void WatchdogService::setInterval(uint64_t interval)
{
    setProperty("Interval", interval);
}

void WatchdogService::setTimeRemaining(uint64_t remaining)
{
    setProperty("TimeRemaining", remaining);
}

ipmi_ret_t ipmi_app_watchdog_reset(
        ipmi_netfn_t netfn,
        ipmi_cmd_t cmd,
        ipmi_request_t request,
        ipmi_response_t response,
        ipmi_data_len_t data_len,
        ipmi_context_t context)
{
    // We never return data with this command so immediately get rid of it
    *data_len = 0;

    try
    {
        WatchdogService wd_service;
        WatchdogProperties wd_prop = wd_service.getProperties();

        // Notify the caller if we haven't initialized our timer yet
        // so it can configure actions and timeouts
        if (!wd_prop.initialized)
        {
            return IPMI_WDOG_CC_NOT_INIT;
        }

        // Reset the countdown to make sure we don't expire our timer
        wd_service.setTimeRemaining(wd_prop.interval);

        // The spec states that the timer is activated by reset
        wd_service.setEnabled(true);

        return IPMI_CC_OK;
    }
    catch (const std::exception& e)
    {
        log<level::ERR>((std::string("wd_get: ") + e.what()).c_str());
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    catch (...)
    {
        log<level::ERR>("wd_reset: Unknown Error");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
}

static constexpr uint8_t wd_dont_stop = 0x1 << 6;
static constexpr uint8_t wd_timeout_action_mask = 0x3;

enum class IpmiAction : uint8_t {
    None = 0x0,
    HardReset = 0x1,
    PowerOff = 0x2,
    PowerCycle = 0x3,
};

/** @brief Converts an IPMI Watchdog Action to DBUS defined action
 *  @param[in] ipmi_action The IPMI Watchdog Action
 *  @return The Watchdog Action that the ipmi_action maps to
 */
Watchdog::Action ipmiActionToWdAction(IpmiAction ipmi_action)
{
    switch(ipmi_action)
    {
        case IpmiAction::None:
        {
            return Watchdog::Action::None;
        }
        case IpmiAction::HardReset:
        {
            return Watchdog::Action::HardReset;
        }
        case IpmiAction::PowerOff:
        {
            return Watchdog::Action::PowerOff;
        }
        case IpmiAction::PowerCycle:
        {
            return Watchdog::Action::PowerCycle;
        }
        default:
        {
            throw std::domain_error("IPMI Action is invalid");
        }
    }
}

struct wd_set_req {
    uint8_t timer_use;
    uint8_t timer_action;
    uint8_t pretimeout;  // (seconds)
    uint8_t expire_flags;
    uint16_t initial_countdown;  // Little Endian (deciseconds)
}  __attribute__ ((packed));
static_assert(sizeof(wd_set_req) == 6, "wd_set_req has invalid size.");
static_assert(sizeof(wd_set_req) <= MAX_IPMI_BUFFER,
        "wd_get_res can't fit in request buffer.");

ipmi_ret_t ipmi_app_watchdog_set(
        ipmi_netfn_t netfn,
        ipmi_cmd_t cmd,
        ipmi_request_t request,
        ipmi_response_t response,
        ipmi_data_len_t data_len,
        ipmi_context_t context)
{
    // Extract the request data
    if (*data_len < sizeof(wd_set_req))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    wd_set_req req;
    memcpy(&req, request, sizeof(req));
    req.initial_countdown = le16toh(req.initial_countdown);
    *data_len = 0;

    try
    {
        WatchdogService wd_service;
        // Stop the timer if the don't stop bit is not set
        if (!(req.timer_use & wd_dont_stop))
        {
            wd_service.setEnabled(false);
        }

        // Set the action based on the request
        const auto ipmi_action = static_cast<IpmiAction>(
                req.timer_action & wd_timeout_action_mask);
        wd_service.setExpireAction(ipmiActionToWdAction(ipmi_action));

        // Set the new interval and the time remaining deci -> mill seconds
        const uint64_t interval = req.initial_countdown * 100;
        wd_service.setInterval(interval);
        wd_service.setTimeRemaining(interval);

        // Mark as initialized so that future resets behave correctly
        wd_service.setInitialized(true);

        return IPMI_CC_OK;
    }
    catch (const std::domain_error &)
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    catch (const std::exception& e)
    {
        log<level::ERR>((std::string("wd_set: ") + e.what()).c_str());
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    catch (...)
    {
        log<level::ERR>("wd_set: Unknown Error");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
}
