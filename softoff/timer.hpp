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
        Timer(const Timer&) = delete;
        Timer& operator=(const Timer&) = delete;
        Timer(Timer&&) = delete;
        Timer& operator=(Timer&&) = delete;

        /** @brief Constructs timer object
         *
         *  @param[in] events - sd_event pointer
         */
        Timer(sd_event* events)
            : timeEvent(events)
        {
            // Initialize the timer
            initialize();
        }

        ~Timer()
        {
            if (eventSource)
            {
                eventSource = sd_event_source_unref(eventSource);
            }
        }

        inline auto isExpired()
        {
            return expired;
        }

    private:
        /** @brief the sd_event structure */
        sd_event* timeEvent = nullptr;

        /** @brief Source of events */
        sd_event_source* eventSource = nullptr;

        /** @brief Returns if the associated timer is expired
         *
         *  This is set to true when the timeoutHandler is called into
         */
        bool expired = false;

        /** @brief Initializes the timer object with infinite
         *         expiration time and sets up the callback handler
         *
         *  @return None.
         *
         *  @error std::runtime exception thrown
         */
        void initialize();

        /** @brief Callback function when timer goes off
         *
         *  On getting the signal, initiate the hard power off request
         *
         *  @param[in] eventSource - Source of the event
         *  @param[in] usec        - time in micro seconds
         *  @param[in] userData    - User data pointer
         *
         */
        static int timeoutHandler(sd_event_source* eventSource,
                                  uint64_t usec, void* userData);
};

} // namespace ipmi
} // namespace phosphor
