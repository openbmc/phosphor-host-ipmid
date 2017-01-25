#pragma once

#include <systemd/sd-event.h>
namespace phosphor
{
namespace ipmi
{

/** @class Timer
 *  @brief Manages starting watchdog timers and handling timeouts
 */
class Timer
{
    public:
        /** @brief Only need the default Timer */
        Timer() = delete;
        ~Timer() = default;
        Timer(const Timer&) = delete;
        Timer& operator=(const Timer&) = delete;
        Timer(Timer&&) = delete;
        Timer& operator=(Timer&&) = default;

        /** @brief Constructs timer object
         *
         *  @param [in] events - sd_event pointer
         *  @param [in] eventSource - event source pointer
         *  @param [in] handler - callback handler in on timeout
         */
        Timer(sd_event* events,
              sd_event_source* eventSource,
              sd_event_time_handler_t handler)
            : expired(false),
              timeEvent(events),
              eventSource(eventSource),
              timeoutHandler(handler)
        {
            // Nothing going on here
        }

        /** @brief Initializes the timer object with infinite
         *         expiration time and sets up the callback handler
         *
         *  @return Success or -1
         */
        int initialize();

        /** @brief Returns if the associated timer is expired
         *
         *  This is set to true when the timeoutHandler is called into
         */
        bool expired;

    private:
        /** @brief the sd_event structure */
        sd_event* timeEvent;

        /** @brief Source of events */
        sd_event_source* eventSource;

        /** @brief Callback handler on timeout */
        sd_event_time_handler_t timeoutHandler;
};

} // namespace ipmi
} // namespace phosphor
