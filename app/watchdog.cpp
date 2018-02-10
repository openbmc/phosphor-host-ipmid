#include "watchdog.hpp"

#include <cstdint>
#include <endian.h>
#include <phosphor-logging/log.hpp>
#include <string>

#include "watchdog_service.hpp"
#include "host-ipmid/ipmid-api.h"
#include "ipmid.hpp"

using phosphor::logging::level;
using phosphor::logging::log;

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
        WatchdogService::Properties wd_prop = wd_service.getProperties();

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
        const std::string e_str = std::string("wd_reset: ") + e.what();
        log<level::ERR>(e_str.c_str());
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
        // Unfortunately we only really support enable or disable
        // and don't actually support a real action. Until we have proper
        // action support just map NONE as a disable action.
        const auto ipmi_action = static_cast<IpmiAction>(
                req.timer_action & wd_timeout_action_mask);
        if (ipmi_action == IpmiAction::None)
        {
            wd_service.setEnabled(false);
        }

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
        const std::string e_str = std::string("wd_set: ") + e.what();
        log<level::ERR>(e_str.c_str());
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    catch (...)
    {
        log<level::ERR>("wd_set: Unknown Error");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
}
