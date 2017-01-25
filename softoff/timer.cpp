#include <phosphor-logging/log.hpp>
#include "timer.hpp"
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

} // namespace ipmi
} // namespace phosphor
