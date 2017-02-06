#include <iostream>
#include <chrono>
#include <gtest/gtest.h>
#include "timer.hpp"

using namespace phosphor::ipmi;

class TimerTest : public ::testing::Test
{
    public:
        // systemd event handler
        sd_event* events;

        // Need this so that events can be initialized.
        int rc;

        // Source of event
        sd_event_source* eventSource;

        // Add a Timer Object
        Timer timer;

        // Gets called as part of each TEST_F construction
        TimerTest()
            : rc(sd_event_default(&events)),
              timer(events)
        {
            // Check for successful creation of
            // event handler and timer object.
            EXPECT_GE(rc, 0);
        }

        // Gets called as part of each TEST_F destruction
        ~TimerTest()
        {
            events = sd_event_unref(events);
        }
};

/** @brief Makes sure that timer is expired and the
 *  callback handler gets invoked post 2 seconds
 */
TEST_F(TimerTest, timerExpiresAfter2seconds)
{
    using namespace std::chrono;

    auto time = duration_cast<microseconds>(seconds(2));
    EXPECT_GE(timer.startTimer(time), 0);

    // Waiting 2 seconds is enough here since we have
    // already spent some usec now
    int count = 0;
    while(count < 2 && !timer.isExpired())
    {
        // Returns -0- on timeout and positive number on dispatch
        auto sleepTime = duration_cast<microseconds>(seconds(1));
        if(!sd_event_run(events, sleepTime.count()))
        {
            count++;
        }
    }
    EXPECT_EQ(true, timer.isExpired());
    EXPECT_EQ(1, count);
}

/** @brief Makes sure that timer is not expired
 */
TEST_F(TimerTest, timerNotExpiredAfter2Seconds)
{
    using namespace std::chrono;

    auto time = duration_cast<microseconds>(seconds(2));
    EXPECT_GE(timer.startTimer(time), 0);

    // Now turn off the timer post a 1 second sleep
    sleep(1);
    EXPECT_GE(timer.setTimer(SD_EVENT_OFF), 0);

    // Wait 2 seconds and see that timer is not expired
    int count = 0;
    while(count < 2)
    {
        // Returns -0- on timeout
        auto sleepTime = duration_cast<microseconds>(seconds(1));
        if(!sd_event_run(events, sleepTime.count()))
        {
            count++;
        }
    }
    EXPECT_EQ(false, timer.isExpired());

    // 2 because of one more count that happens prior to exiting
    EXPECT_EQ(2, count);
}

/** @brief Makes sure that timer value is changed in between
 *  and that the new timer expires
 */
TEST_F(TimerTest, updateTimerAndExpectExpire)
{
    using namespace std::chrono;

    auto time = duration_cast<microseconds>(seconds(2));
    EXPECT_GE(timer.startTimer(time), 0);

    // Now sleep for a second and then set the new timeout value
    sleep(1);

    // New timeout is 3 seconds from THIS point.
    time = duration_cast<microseconds>(seconds(3));
    EXPECT_GE(timer.startTimer(time), 0);

    // Wait 3 seconds and see that timer is expired
    int count = 0;
    while(count < 3 && !timer.isExpired())
    {
        // Returns -0- on timeout
        auto sleepTime = duration_cast<microseconds>(seconds(1));
        if(!sd_event_run(events, sleepTime.count()))
        {
            count++;
        }
    }
    EXPECT_EQ(true, timer.isExpired());
    EXPECT_EQ(2, count);
}

/** @brief Makes sure that timer value is changed in between
 *  and turn off and make sure that timer does not expire
 */
TEST_F(TimerTest, updateTimerAndNeverExpire)
{
    using namespace std::chrono;

    auto time = duration_cast<microseconds>(seconds(2));
    EXPECT_GE(timer.startTimer(time), 0);

    // Now sleep for a second and then set the new timeout value
    sleep(1);

    // New timeout is 2 seconds from THIS point.
    time = duration_cast<microseconds>(seconds(2));
    EXPECT_GE(timer.startTimer(time), 0);

    // Now turn off the timer post a 1 second sleep
    sleep(1);
    EXPECT_GE(timer.setTimer(SD_EVENT_OFF), 0);

    // Wait 2 seconds and see that timer is expired
    int count = 0;
    while(count < 2)
    {
        // Returns -0- on timeout
        auto sleepTime = duration_cast<microseconds>(seconds(1));
        if(!sd_event_run(events, sleepTime.count()))
        {
            count++;
        }
    }
    EXPECT_EQ(false, timer.isExpired());

    // 2 becase of one more count that happens prior to exiting
    EXPECT_EQ(2, count);
}
