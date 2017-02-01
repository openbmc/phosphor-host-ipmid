#include <chrono>
#include "timer.hpp"
#include <log.hpp>
namespace phosphor
{
namespace ipmi
{

using namespace phosphor::logging;

/** @brief Initializes the timer object */
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
    r = setTimer(SD_EVENT_OFF);
    if (r < 0)
    {
        log<level::ERR>("Failure to disable timer",
                entry("ERROR=%s", strerror(-r)));
    }
    return r;
}

/** @brief Gets the time from specified type, could be
 *  CLOCK_MONOTONIC, CLOCK_REALTIME and other allowed ones
 */
uint64_t Timer::getTime(clockid_t clockId)
{
    using namespace std::chrono;

    struct timespec ts {};

    auto r = clock_gettime(clockId, &ts);
    if (r < 0)
    {
        log<level::ERR>("Failure to get clock time",
                entry("ERROR=%s", strerror(-r)));
        return 0;
    }

    // Need to convert to 64 bit nano seconds
    auto time = duration_cast<nanoseconds>(seconds(ts.tv_sec));
    time += duration_cast<nanoseconds>(nanoseconds(ts.tv_nsec));

    // Absoulte count in 64 bit precision
    return time.count();
}

/** @brief Enables or disables the timer */
int Timer::setTimer(int action)
{
    return sd_event_source_set_enabled(eventSource, action);
}

/** @brief Sets the time and arms the timer */
int Timer::startTimer(uint64_t timeValue)
{
    // Disable the timer
    setTimer(SD_EVENT_OFF);

    // Get the current MONOTONIC time and add the delta
    auto expireTime = getTime(CLOCK_MONOTONIC) + timeValue;

    // Set the time
    auto r = sd_event_source_set_time(eventSource, expireTime);
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
