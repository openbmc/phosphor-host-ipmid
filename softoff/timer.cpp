#include <phosphor-logging/log.hpp>
#include "timer.hpp"
namespace phosphor
{
namespace ipmi
{

using namespace phosphor::logging;

// Initializes the timer object
void Timer::initialize()
{
    // This can not be called more than once.
    if (eventSource)
    {
        throw std::runtime_error("Timer already initialized");
    }

    // Add infinite expiration time
    auto r = sd_event_add_time(timeEvent, &eventSource,
                               CLOCK_MONOTONIC, // Time base
                               UINT64_MAX,      // Expire time - way long enough time
                               0,               // Use default event accuracy
                               timeoutHandler,  // Callback handler on timeout
                               this);           // User data
    if (r < 0)
    {
        log<level::ERR>("Failure to set initial expiration time value",
                entry("ERROR=%s", strerror(-r)));

        throw std::runtime_error("Timer initialization failed");
    }

    // Disable the timer for now
    r = sd_event_source_set_enabled(eventSource, SD_EVENT_OFF);
    if (r < 0)
    {
        log<level::ERR>("Failure to disable timer",
                entry("ERROR=%s", strerror(-r)));

        throw std::runtime_error("Setting initial timer value failed");
    }
    return;
}

/** @brief callback handler on timeout */
int Timer::timeoutHandler(sd_event_source* eventSource,
                          uint64_t usec, void* userData)
{
    auto timer = static_cast<Timer*>(userData);
    timer->expired = true;

    log<level::INFO>("Timer expired");
    return 0;
}

} // namespace ipmi
} // namespace phosphor
