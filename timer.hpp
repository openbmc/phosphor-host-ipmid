#pragma once

#include <systemd/sd-event.h>

#include <chrono>
#include <functional>
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
     *  @param[in] funcCallBack - optional function callback for timer
     *                            expirations
     */
    Timer(sd_event* events, std::function<void()> userCallBack = nullptr) :
        timeEvent(events), userCallBack(userCallBack)
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

    inline auto isExpired() const
    {
        return expired;
    }

    /** @brief Starts the timer with specified expiration value.
     *  input is an offset from the current steady_clock
     */
    int startTimer(std::chrono::microseconds usec);

    /** @brief Enables / disables the timer */
    int setTimer(int action);

  private:
    /** @brief the sd_event structure */
    sd_event* timeEvent = nullptr;

    /** @brief Source of events */
    sd_event_source* eventSource = nullptr;

    /** @brief Returns if the associated timer is expired
     *
     *  This is set to true when the timeoutHandler is called into
     */
    bool expired = true;

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
    static int timeoutHandler(sd_event_source* eventSource, uint64_t usec,
                              void* userData);

    /** @brief Gets the current time from steady clock */
    static std::chrono::microseconds getTime();

    /** @brief Optional function to call on timer expiration */
    std::function<void()> userCallBack;
};

} // namespace ipmi
} // namespace phosphor
