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
        Timer(const Timer&) = delete;
        Timer& operator=(const Timer&) = delete;
        Timer(Timer&&) = delete;
        Timer& operator=(Timer&&) = default;

        /** @brief Constructs timer object
         *
         *  @param [in] bus - sdbusplus handle
         *  @param [in] events - sd_event pointer
         *  @param [in] eventSource - event source pointer
         *  @param [in] handler - callback handler in on timeout
         */
        Timer(sdbusplus::bus::bus& bus, sd_event* events,
              sd_event_source* eventSource,
              sd_event_time_handler_t handler)
            : bus(bus),
              timeEvent(events),
              eventSource(eventSource),
              timeoutHandler(handler),
              expired(false)
        {
            // Attach the 'event' handler to bus so that we get signals
            bus.attach_event(timeEvent, SD_EVENT_PRIORITY_NORMAL);
        }

        /** @brief Destroys timer object */
        ~Timer()
        {
            bus.detach_event();
        }

        /** @brief Initializes the timer object with infinite
         *         expiration time and setsup the callback handler
         *
         *  @return Success or -1
         */
        int initialize();

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

        /** @brief Callback handler on timeout */
        sd_event_time_handler_t timeoutHandler;

        /** @brief Whether the timer is expired or not */
        bool expired;
};

} // namespace ipmi
} // namespace phosphor
