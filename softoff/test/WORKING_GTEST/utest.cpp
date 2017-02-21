#include <iostream>
#include <assert.h>
#include <chrono>
#include <gtest/gtest.h>
#include "timer.hpp"
#include <assert.h>

using namespace phosphor::ipmi;

// Exit helpers. Ideally should be class but need
// this to be used inside a static method.
bool timerExpired;
bool testCompleted;

// systemd event handler
sd_event* events;
sd_event_source* eventSource;

class TimerTest : public ::testing::Test
{
    public:
        // Gets called as part of each TEST_F construction
        virtual void SetUp()
        {
            events = nullptr;
            eventSource = nullptr;
            timerExpired = false;
            testCompleted = false;
        }

        // Gets called as part of each TEST_F destruction
        virtual void TearDown()
        {
            sd_event_source_unref(eventSource);
            sd_event_unref(events);

            events = nullptr;
            eventSource = nullptr;
            timerExpired = false;
            testCompleted = false;
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

        // Callback handler on timeout conditions.
/*int        timeOutHandler(sd_event_source* eventSource,
                          uint64_t usec, void* userData)
        {
            std::cout <<"VISHWA Watchdog Timed Out " << std::endl;
            assert(false);
            timerExpired = true;
            return 0;
        }
        */
/** @brief Makes sure that timer object can be created and initialized */
TEST_F(TimerTest, initTimerObject)
{
    using namespace std::chrono;

    sd_event_default(&events);
    auto bus = sdbusplus::bus::new_default();
    Timer timer(bus, events, eventSource, timeOutHandler);

    // Initialize the timer object
    EXPECT_GE(0, timer.initialize());

    auto time = duration_cast<microseconds>(seconds(5));
    timer.startTimer(time.count());

    sd_event_loop(events);

 /*   while(!timerExpired && !testCompleted)
    {
        sd_event_run(bus.get_event(), (uint64_t)-1);
    }*/
}
