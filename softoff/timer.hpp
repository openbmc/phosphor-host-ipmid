#pragma once

#include <systemd/sd-event.h>
#include <sdbusplus/bus.hpp>
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
         *  @param [in] bus - sdbusplus handle
         */
        Timer(sdbusplus::bus::bus& bus, sd_event* events)
            : bus(bus),
              timeEvent(events),
              eventSource(nullptr),
              expired(false)
        {
            // Attach the 'event' handler to bus so that we get signals
            bus.attach_event(timeEvent, SD_EVENT_PRIORITY_NORMAL);
        }

        /** @brief Initializes the timer object with infinite
         *         expiration time
         */
        int initTimer();

        /** @brief Returns if the timer is currently expired or not */
        inline auto isExpired()
        {
            return expired;
        }

    private:
        /** @brief Reference to passed in bus handler */
        sdbusplus::bus::bus& bus;

        /** @brief the sd_event structure */
        sd_event* timeEvent;

        /** @brief Source of events */
        sd_event_source* eventSource;

        /** @brief Callback function when timer goes off
         *
         *  On getting the signal, initiate the hard power off request
         *
         *  @param[in] msg        - Source of the event
         *  @param[in] usec       - time in micro seconds
         *  @param[in] userData   - User data pointer
         *
         */
        static int timeoutHandler(sd_event_source* eventSource,
                                  uint64_t usec, void* userData);

        /** @brief Whether the timer is expired or not */
        bool expired;
};

} // namespace ipmi
} // namespace phosphor
