#include "timer.hpp"
#include <log.hpp>
namespace phosphor
{
namespace ipmi
{

using namespace phosphor::logging;

// Initializes the timer object
int Timer::initialize()
{
    // Add infinite expiration time
    auto r = sd_event_add_time(timeEvent, &eventSource,
                               CLOCK_MONOTONIC, // Time base
                               UINT_MAX,        // Expire time - never
                               0,               // Use default event accuracy
                               timeoutHandler,  // Callback handler on timeout
                               this);           // User data
    if (r < 0)
    {
        log<level::ERR>("Failure to set initial expiration time value",
                entry("ERROR=%s", strerror(-r)));
        return r;
    }

    // Disable the timer for now
    r = sd_event_source_set_enabled(eventSource, SD_EVENT_OFF);
    if (r < 0)
    {
        log<level::ERR>("Failure to disable timer",
                entry("ERROR=%s", strerror(-r)));
    }
    return r;
}

// Timeout callback handler
int Timer::timeoutHandler(sd_event_source* eventSource,
                          uint64_t usec, void* userData)
{
    // Get the handle to this object that was bound during registration
    auto thisObject = static_cast<Timer*>(userData);

    // The only thing that is to be done here is to make a call
    // to Chassis object to do Hard Power Off.
    auto method = thisObject->bus.new_method_call(CHASSIS_SERVICE,
                                                  CHASSIS_OBJ,
                                                  PROPERTY_INTF,
                                                  "Set");

    // Fill the Interface, property name and its value.
    method.append(CHASSIS_INTF,
                  "RequestedPowerTransition",
                  CHASSIS_OFF);

    // Set the property.
    thisObject->bus.call(method);

    // The timer is now considerd 'expired` !!
    thisObject->expired = true;

    return 0;
}

} // namespace ipmi
} // namespace phosphor
