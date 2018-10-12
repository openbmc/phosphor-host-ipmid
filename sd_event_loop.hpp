#pragma once

#include "sol/sol_manager.hpp"

#include <systemd/sd-event.h>

#include <chrono>
#include <map>

namespace eventloop
{

/** @struct EventSourceDeleter
 *
 *  Custom deleter for the sd_event_source*.
 */
struct EventSourceDeleter
{
    void operator()(sd_event_source* event) const
    {
        event = sd_event_source_unref(event);
    }
};

using EventSource = std::unique_ptr<sd_event_source, EventSourceDeleter>;
using IntervalType = std::chrono::microseconds;

/** @enum Timers
 *
 *  For SOL functioning, there are two timers involved. The character accumulate
 *  interval timer is the amount of time that the BMC will wait before
 *  transmitting a partial SOL packet. The retry interval timer is the time that
 *  BMC will wait before the first retry and the time between retries when
 *  sending SOL packets to the remote console.
 */
enum class Timers
{
    ACCUMULATE, /**< Character Accumulate Timer */
    RETRY,      /**< Retry Interval Timer */
};

class EventLoop
{
  public:
    EventLoop() = default;
    ~EventLoop() = default;
    EventLoop(const EventLoop&) = delete;
    EventLoop& operator=(const EventLoop&) = delete;
    EventLoop(EventLoop&&) = delete;
    EventLoop& operator=(EventLoop&&) = delete;

    /** @brief Timer Map
     *
     *  The key for the timer map is the timer type. There are two types of
     *  timers, character accumulate timer and retry interval timer. The
     *  entries in the values is the event source for the timer and the
     *  interval.
     */
    using TimerMap = std::map<Timers, std::tuple<EventSource, IntervalType>>;

    /** @brief SOL Payload Map.
     *
     *  The key for the payload map is the payload instance, the entries in
     *  the value are a map of timers.
     */
    using PayloadMap = std::map<uint8_t, TimerMap>;

    /** @brief Initialise the event loop and add the handler for incoming
     *         IPMI packets.
     *  @param[in] events- sd bus event;
     *
     *  @return EXIT_SUCCESS on success and EXIT_FAILURE on failure.
     */
    int startEventLoop(sd_event* events);

    /** @brief Add host console I/O event source to the event loop.
     *
     *  @param[in] fd - File descriptor for host console socket.
     */
    void startHostConsole(const sol::CustomFD& fd);

    /** @brief Remove host console I/O event source. */
    void stopHostConsole();

    /** @brief Initialize the timers for the SOL payload instance
     *
     *  This API would add the Character accumulate interval timer event
     *  source and the retry interval timer event source for the SOL payload
     *  instance to the event loop.
     *
     *  @param[in] payloadInst - SOL payload instance.
     *  @param[in] accumulateInterval - Character accumulate interval.
     *  @param[in] retryInterval - Retry interval.
     */
    void startSOLPayloadInstance(uint8_t payloadInst,
                                 IntervalType accumulateInterval,
                                 IntervalType retryInterval);

    /** @brief Stop the timers for the SOL payload instance.
     *
     *  This would remove the character accumulate interval timer event
     *  source and the retry interval timer event source from the event
     *  loop.
     *
     *  @param[in] payloadInst - SOL payload instance
     */
    void stopSOLPayloadInstance(uint8_t payloadInst);

    /** @brief Modify the timer event source to enable/disable.
     *
     *  When the timer is enabled, the timer it set to fire again at
     *  timer's interval for the instance added to the event loop iteration
     *  timestamp. When the timer is disabled, the event source for the
     *  timer is disabled.
     *
     *  @param[in] payloadInst - SOL payload instance.
     *  @param[in] type -  Timer type.
     *  @param[in] status - on/off the event source.
     */
    void switchTimer(uint8_t payloadInst, Timers type, bool status);

    /** @brief Modify the retry interval timer event source to enable/
     *         disable
     *
     *  When the timer is enabled, the timer it set to fire again at
     *  retry interval for the instance added to the event loop iteration
     *  timestamp. When the timer is disabled the event source for the
     *  retry interval timer is disabled.
     *
     *  @param[in] payloadInst - SOL payload instance.
     *  @param[in] status - on/off the event source.
     */
    void switchRetryTimer(uint8_t payloadInst, bool status);

    /** @brief Event loop object. */
    sd_event* event = nullptr;

  private:
    /** @brief Event source object for host console. */
    EventSource hostConsole = nullptr;

    /** @brief Event source for the UDP socket listening on IPMI standard
     *         port.
     */
    EventSource udpIPMI = nullptr;

    /** @brief Map to keep information regarding IPMI payload instance and
     *         timers for character accumulate interval and retry interval.
     */
    PayloadMap payloadInfo;
};

} // namespace eventloop
