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
        Timer& operator=(Timer&&) = delete;

        /** @brief Constructs timer object
         *
         *  @param [in] events - sd_event pointer
         *  @param [in] handler - callback handler in on timeout
         */
        Timer(sd_event* events,
              sd_event_time_handler_t handler)
            : timeEvent(events),
              eventSource(nullptr),
              timeoutHandler(handler)
        {
            // Nothing going on here
        }

        /** @brief Initializes the timer object with infinite
         *         expiration time and sets up the callback handler
         *
         *  @param [in] userData - bound to data
         *
         *  @return None.
         *
         *  @error std::runtime exception thrown
         */
        void initialize(void* userData);

        /** @brief Returns if the associated timer is expired
         *
         *  This is set to true when the timeoutHandler is called into
         */
        bool expired = false;

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
