#include "timer.hpp"

#include <chrono>
#include <phosphor-logging/log.hpp>
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
                               UINT64_MAX,      // Expire time - way long time
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
    r = setTimer(SD_EVENT_OFF);
    if (r < 0)
    {
        log<level::ERR>("Failure to disable timer",
                        entry("ERROR=%s", strerror(-r)));

        throw std::runtime_error("Disabling the timer failed");
    }
    return;
}

/** @brief callback handler on timeout */
int Timer::timeoutHandler(sd_event_source* eventSource, uint64_t usec,
                          void* userData)
{
    auto timer = static_cast<Timer*>(userData);
    timer->expired = true;

    log<level::INFO>("Timer expired");
    // Call optional user call back function if available
    if (timer->userCallBack)
    {
        timer->userCallBack();
    }

    sd_event_source_set_enabled(eventSource, SD_EVENT_OFF);
    return 0;
}

// Gets the time from steady_clock
std::chrono::microseconds Timer::getTime()
{
    using namespace std::chrono;
    auto usec = steady_clock::now().time_since_epoch();
    return duration_cast<microseconds>(usec);
}

// Enables or disables the timer
int Timer::setTimer(int action)
{
    return sd_event_source_set_enabled(eventSource, action);
}

// Sets the time and arms the timer
int Timer::startTimer(std::chrono::microseconds timeValue)
{
    // Disable the timer
    setTimer(SD_EVENT_OFF);
    expired = false;

    // Get the current MONOTONIC time and add the delta
    auto expireTime = getTime() + timeValue;

    // Set the time
    auto r = sd_event_source_set_time(eventSource, expireTime.count());
    if (r < 0)
    {
        log<level::ERR>("Failure to set timer",
                        entry("ERROR=%s", strerror(-r)));
        return r;
    }

    // A ONESHOT timer means that when the timer goes off,
    // its moves to disabled state.
    r = setTimer(SD_EVENT_ONESHOT);
    if (r < 0)
    {
        log<level::ERR>("Failure to start timer",
                        entry("ERROR=%s", strerror(-r)));
    }
    return r;
}

} // namespace ipmi
} // namespace phosphor
