#include <iostream>
#include <chrono>
#include <gtest/gtest.h>
#include "timer.hpp"

using namespace phosphor::ipmi;

// Exit helper. Ideally should be class but need
// this to be used inside a static method.
bool timerExpired {};

class TimerTest : public ::testing::Test
{
    public:
        // systemd event handler
        sd_event* events;
        sd_event_source* eventSource;

        // Gets called as part of each TEST_F construction
        virtual void SetUp()
        {
            // Create a sd_event structure
            EXPECT_LE(0, sd_event_default(&events));

            eventSource = nullptr;
            timerExpired = false;
        }

        // Gets called as part of each TEST_F destruction
        virtual void TearDown()
        {
            eventSource = sd_event_source_unref(eventSource);
            events = sd_event_unref(events);
            timerExpired = false;
        }

        // Callback handler on timeout conditions.
        static int timeOutHandler(sd_event_source* eventSource,
                                  uint64_t usec, void* userData)
        {
            std::cout <<"Watchdog Timed Out " << std::endl;
            timerExpired = true;
            return 0;
        }
};

/** @brief Makes sure that timer object can be created
 *  and initialized and that it gets called on a timeout
 */
TEST_F(TimerTest, initTimerObject)
{
    // Create a bus handler
    auto bus = sdbusplus::bus::new_default();

    // And a Timer Object
    Timer timer(bus, events, eventSource, timeOutHandler);

    // Initialize the timer object.
    // sd_event_source_set_enabled returns non -ve number on success
    EXPECT_GE(timer.initialize(), 0);
}

/** @brief Makes sure that timeout routine gets
 *  called post 3 seconds
 */
TEST_F(TimerTest, timeOutAfter3seconds)
{
    using namespace std::chrono;

    // Create a bus handler
    auto bus = sdbusplus::bus::new_default();

    // And a Timer Object
    Timer timer(bus, events, eventSource, timeOutHandler);

    // Initialize the timer object
    // sd_event_source_set_enabled returns non -ve number on success
    EXPECT_GE(timer.initialize(), 0);

    auto time = duration_cast<microseconds>(seconds(2));
    timer.startTimer(time.count());

    // Wait only 2 second more than what we are supposed to wait.
    int count = 0;
    while(count++ < 4)
    {
        // Returns -0- on timeout and positive number on dispatch
        auto sleepTime = duration_cast<microseconds>(seconds(1));
        if(sd_event_run(bus.get_event(), sleepTime.count()))
        {
            sleep(1);
        }
    }
    EXPECT_EQ(true, timerExpired);
}

/** @brief Makes sure that timeout is not hit
 */
TEST_F(TimerTest, allGoodNoTimeout)
{
    using namespace std::chrono;

    // Create a bus handler
    auto bus = sdbusplus::bus::new_default();

    // And a Timer Object
    Timer timer(bus, events, eventSource, timeOutHandler);

    // Initialize the timer object
    // sd_event_source_set_enabled returns non -ve number on success
    EXPECT_GE(timer.initialize(), 0);

    auto time = duration_cast<microseconds>(seconds(2));
    timer.startTimer(time.count());

    // Now turn off the timer post a 1 second sleep
    sleep(1);
    timer.setTimer(SD_EVENT_OFF);

    // Wait 2 seconds and see that timer is not expired
    int count = 0;
    while(count++ < 2)
    {
        // Returns -0- on timeout
        auto sleepTime = duration_cast<microseconds>(seconds(1));
        if(sd_event_run(bus.get_event(), sleepTime.count()))
        {
            sleep(1);
        }
    }
    EXPECT_EQ(false, timerExpired);
}

/** @brief Makes sure that timeout is changed in between
 *  and the new timeout is hit
 */
TEST_F(TimerTest, updateTimerAndExpectNewTimeout)
{
    using namespace std::chrono;

    // Create a bus handler
    auto bus = sdbusplus::bus::new_default();

    // And a Timer Object
    Timer timer(bus, events, eventSource, timeOutHandler);

    // Initialize the timer object
    // sd_event_source_set_enabled returns non -ve number on success
    EXPECT_GE(timer.initialize(), 0);

    auto time = duration_cast<microseconds>(seconds(2));
    timer.startTimer(time.count());

    // Now sleep for a second and then set the new timeout value
    sleep(1);

    // New timeout is 3 seconds from THIS point.
    time = duration_cast<microseconds>(seconds(3));
    timer.startTimer(time.count());

    // Wait 5 seconds and see that timer is expired
    int count = 0;
    while(count++ < 5)
    {
        // Returns -0- on timeout
        auto sleepTime = duration_cast<microseconds>(seconds(1));
        if(sd_event_run(bus.get_event(), sleepTime.count()))
        {
            sleep(1);
        }
    }
    EXPECT_EQ(true, timerExpired);
}

/** @brief Makes sure that timeout is changed in between
 *  and turn off and make sure that timeout is not hit
 */
TEST_F(TimerTest, updateTimerAndExpectNoTimeout)
{
    using namespace std::chrono;

    // Create a bus handler
    auto bus = sdbusplus::bus::new_default();

    // And a Timer Object
    Timer timer(bus, events, eventSource, timeOutHandler);

    // Initialize the timer object
    // sd_event_source_set_enabled returns non -ve number on success
    EXPECT_GE(timer.initialize(), 0);

    auto time = duration_cast<microseconds>(seconds(2));
    timer.startTimer(time.count());

    // Now sleep for a second and then set the new timeout value
    sleep(1);

    // New timeout is 2 seconds from THIS point.
    time = duration_cast<microseconds>(seconds(2));
    timer.startTimer(time.count());

    // Now turn off the timer post a 1 second sleep
    sleep(1);
    timer.setTimer(SD_EVENT_OFF);

    // Wait 3 seconds and see that timer is expired
    int count = 0;
    while(count++ < 3)
    {
        // Returns -0- on timeout
        auto sleepTime = duration_cast<microseconds>(seconds(1));
        if(sd_event_run(bus.get_event(), sleepTime.count()))
        {
            sleep(1);
        }
    }
    EXPECT_EQ(false, timerExpired);
}
