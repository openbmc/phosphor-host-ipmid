#include "watchdog.hpp"
#include "utils.hpp"
#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog-errors.hpp>

#include <systemd/sd-bus.h>

#include <mapper.h>
#include <sdbusplus/bus.hpp>
#include <map>

namespace pl = phosphor::logging;

extern sd_bus *bus;

/* These bits are defined by the IPMI spec to set what
 * who owns this timer, whether it's the BIOS, or the OS,
 * or other, and is only for logging purposes if logging
 * is enabled.
 */
enum class TimerUse : uint8_t
{
    BIOS_FRB2 = 1,
    BIOS_POST = 2,
    OS_LOAD = 3,
    SMS_OS = 4,
    OEM = 5,
};

/* These bits are defined by the IPMI spec to set what
 * action should be taken on timeout.  The current phosphor
 * mechanism only allows specifying one target and its behavior
 * is not dynamic for timeouts.  Therefore, we presently only
 * support either NONE or HARD_RESET and with NONE, we simply
 * disable the timer.
 */
enum class TimeoutAction : uint8_t
{
    NONE = 0,
    HARD_RESET = 1,
    POWER_DOWN = 2,
    POWER_CYCLE = 3,
};

struct wd_data_t {
    uint8_t timer_use;
    uint8_t timer_action;
    uint8_t preset;
    uint8_t flags;
    uint8_t ls;
    uint8_t ms;
}  __attribute__ ((packed));

struct get_wd_data_t {
    struct wd_data_t config;
    uint8_t remains_ls;
    uint8_t remains_ms;
}  __attribute__ ((packed));

// Cache the watchdog state.  This initialized to nothing is updated
// by the set watchdog command and read back by the get watchdog command.
//
// It's necessary to cache this information because the phosphor-watchdog
// doesn't store and expose all the fields.  The get watchdog command reads
// back the dynamic information over dbus.
//
static struct wd_data_t watchdogState = {0, 0, 0, 0, 0, 0};

static constexpr auto objname = "/xyz/openbmc_project/watchdog/host0";
static constexpr auto iface = "xyz.openbmc_project.State.Watchdog";
static constexpr auto property_iface = "org.freedesktop.DBus.Properties";
static constexpr auto expected_properties = 3;

// ProperyMap corresponding to the current properties of the State.Watchdog
// interface.
using PropertyMap = std::map<std::string,
                             sdbusplus::message::variant<uint64_t, bool>>;

ipmi_ret_t ipmi_app_set_watchdog(
        ipmi_netfn_t netfn,
        ipmi_cmd_t cmd,
        ipmi_request_t request,
        ipmi_response_t response,
        ipmi_data_len_t data_len,
        ipmi_context_t context)
{
    sd_bus_message *reply = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int r = 0;

    // Check if dataLen is the right size.
    if (*data_len != sizeof(struct wd_data_t))
    {
        *data_len = 0;
        return IPMI_CC_INVALID;
    }

    auto reqptr = static_cast<wd_data_t *>(request);

    // Store the configuration.
    memcpy(&watchdogState, reqptr, sizeof(watchdogState));
    uint16_t timer = 0;

    // Making this uint64_t to match with provider
    uint64_t timer_ms = 0;
    char *busname = NULL;
    *data_len = 0;

    // Get number of 100ms intervals
    timer = (((uint16_t)reqptr->ms) << 8) + reqptr->ls;
    // Get timer value in ms
    timer_ms = timer * 100;

    printf("WATCHDOG SET Timer:[0x%X] 100ms intervals\n",timer);

    // Get bus name
    r = mapper_get_service(bus, objname, &busname);
    if (r < 0) {
        fprintf(stderr, "Failed to get %s bus name: %s\n",
                objname, strerror(-r));
        goto finish;
    }

    // Disable watchdog if running
    r = sd_bus_call_method(bus, busname, objname, property_iface,
                           "Set", &error, &reply, "ssv",
                           iface, "Enabled", "b", false);
    if(r < 0) {
        fprintf(stderr, "Failed to disable Watchdog: %s\n",
                    strerror(-r));
        goto finish;
    }

    /*
     * If the action is 0, it means, do nothing.  Multiple actions on timer
     * expiration aren't supported by phosphor-watchdog yet, so when the
     * action set is "none", we should just leave the timer disabled.
     */
    if ((reqptr->timer_action & 0x7) ==
        static_cast<uint8_t>(TimeoutAction::NONE))
    {
        goto finish;
    }

    if (reqptr->timer_use & 0x40)
    {
        sd_bus_error_free(&error);
        reply = sd_bus_message_unref(reply);

        // Set the Interval for the Watchdog
        r = sd_bus_call_method(bus, busname, objname, property_iface,
                               "Set", &error, &reply, "ssv",
                               iface, "Interval", "t", timer_ms);
        if(r < 0) {
            fprintf(stderr, "Failed to set new expiration time: %s\n",
                    strerror(-r));
            goto finish;
        }

        // Now Enable Watchdog
        r = sd_bus_call_method(bus, busname, objname, property_iface,
                               "Set", &error, &reply, "ssv",
                               iface, "Enabled", "b", true);
        if(r < 0) {
            fprintf(stderr, "Failed to Enable Watchdog: %s\n",
                    strerror(-r));
            goto finish;
        }
    }

finish:
    sd_bus_error_free(&error);
    reply = sd_bus_message_unref(reply);
    free(busname);

    return (r < 0) ? -1 : IPMI_CC_OK;
}

ipmi_ret_t ipmi_app_get_watchdog(
        ipmi_netfn_t netfn,
        ipmi_cmd_t cmd,
        ipmi_request_t request,
        ipmi_response_t response,
        ipmi_data_len_t data_len,
        ipmi_context_t context)
{
    auto data = static_cast<struct get_wd_data_t *>(response);

    // Start with the configuration.  However, the values aren't guaranteed
    // to remain unmodified.
    memcpy(&data->config, &watchdogState, sizeof(watchdogState));

    // Default to failure.
    *data_len = 0;

    sdbusplus::bus::bus bus(ipmid_get_sd_bus_connection());

    std::string watchdogService;
    try
    {
        // Get the service (just in case it's not what we expect)
        watchdogService = ipmi::getService(
                bus, iface, objname);
    }
    catch (const std::runtime_error& error)
    {
        pl::log<pl::level::ERR>("Failed to grab watchdog service");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    // Get the current state for the action field
    auto pMsg = bus.new_method_call(watchdogService.c_str(),
                                    objname,
                                    property_iface,
                                    "GetAll");
    pMsg.append(iface);
    auto responseMsg = bus.call(pMsg);
    if (responseMsg.is_method_error())
    {
        pl::log<pl::level::ERR>("Failed to get properties of watchdog");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    PropertyMap propMap;
    responseMsg.read(propMap);

    // We expect at least three properties.
    if (propMap.size() < expected_properties)
    {
        pl::log<pl::level::ERR>("Failed to get properties of watchdog");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    auto enabled = sdbusplus::message::variant_ns::get<bool>(
            propMap["Enabled"]);
    auto timeRemaining = sdbusplus::message::variant_ns::get<uint64_t>(
            propMap["TimeRemaining"]);
    auto interval = sdbusplus::message::variant_ns::get<uint64_t>(
            propMap["Interval"]);

    // timer_use we'll leave to whatever it was set via IPMI.

    // If enabled, timer_action are set accordingly.

    // The timeout action is the lowest 3 bits, so only set those.
    // Clear the lowest 3, &= ~7 might be easier to read?
    data->config.timer_action &= 0xf8;

    if (enabled)
    {
        // If phosphor-watchdog allows specifying a target based on the action,
        // then conceivably there could be a variation in the action field.
        // https://github.com/openbmc/openbmc/issues/2522
        //
        data->config.timer_action |= static_cast<uint8_t>(TimeoutAction::HARD_RESET);
    }

    // Set Interval
    interval /= 100;
    data->config.ls = static_cast<uint8_t>(interval);
    data->config.ms = static_cast<uint8_t>(interval >> 8);

    // Set TimeRemaining
    timeRemaining /= 100;
    data->remains_ls = static_cast<uint8_t>(timeRemaining);
    data->remains_ms = static_cast<uint8_t>(timeRemaining >> 8);

    *data_len = sizeof(struct get_wd_data_t);
    return IPMI_CC_OK;
}

ipmi_ret_t ipmi_app_reset_watchdog(
        ipmi_netfn_t netfn,
        ipmi_cmd_t cmd,
        ipmi_request_t request,
        ipmi_response_t response,
        ipmi_data_len_t data_len,
        ipmi_context_t context)
{
    sd_bus_message *reply = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int r = 0;
    char *busname = NULL;

    // Current properties of the watchdog daemon.
    int enabled = 0;
    uint64_t interval = 0;

    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;

    printf("WATCHDOG RESET\n");
    // Get bus name
    r = mapper_get_service(bus, objname, &busname);
    if (r < 0) {
        fprintf(stderr, "Failed to get %s bus name: %s\n",
                objname, strerror(-r));
        goto finish;
    }

    // Check if our watchdog is running
    r = sd_bus_call_method(bus, busname, objname, property_iface,
                           "Get", &error, &reply, "ss",
                           iface, "Enabled");
    if(r < 0) {
        fprintf(stderr, "Failed to get current Enabled msg: %s\n",
                strerror(-r));
        goto finish;
    }

    // Now extract the value
    r = sd_bus_message_read(reply, "v", "b", &enabled);
    if (r < 0) {
        fprintf(stderr, "Failed to read current Enabled: %s\n",
                strerror(-r));
        goto finish;
    }

    // If we are not enable we should indicate that
    if (!enabled) {
        printf("Watchdog not enabled during reset\n");
        rc = IPMI_WDOG_CC_NOT_INIT;
        goto finish;
    }

    sd_bus_error_free(&error);
    reply = sd_bus_message_unref(reply);

    // Get the current interval and set it back.
    r = sd_bus_call_method(bus, busname, objname, property_iface,
                           "Get", &error, &reply, "ss",
                           iface, "Interval");

    if(r < 0) {
        fprintf(stderr, "Failed to get current Interval msg: %s\n",
                strerror(-r));
        goto finish;
    }

    // Now extract the value
    r = sd_bus_message_read(reply, "v", "t", &interval);
    if (r < 0) {
        fprintf(stderr, "Failed to read current interval: %s\n",
                strerror(-r));
        goto finish;
    }

    sd_bus_error_free(&error);
    reply = sd_bus_message_unref(reply);

    // Set watchdog timer
    r = sd_bus_call_method(bus, busname, objname, property_iface,
                           "Set", &error, &reply, "ssv",
                           iface, "TimeRemaining", "t", interval);
    if(r < 0) {
        fprintf(stderr, "Failed to refresh the timer: %s\n",
                strerror(-r));
        goto finish;
    }

finish:
    sd_bus_error_free(&error);
    reply = sd_bus_message_unref(reply);
    free(busname);

    return rc;
}
