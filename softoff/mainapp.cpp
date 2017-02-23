/**
 * Copyright © 2016 IBM Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <chrono>
#include <systemd/sd-event.h>
#include <phosphor-logging/elog.hpp>
#include "elog-errors-SoftOffHost.hpp"
#include "softoff.hpp"
#include "config.h"
#include "timer.hpp"

int main(int argc, char** argv)
{
    using namespace phosphor::logging;
    using namespace std::chrono;

    // systemd event handler
    sd_event* events = nullptr;
    sd_event_source* eventSource = nullptr;

    // Get a handle to system dbus.
    auto bus = sdbusplus::bus::new_default();

    // Add systemd object manager.
    sdbusplus::server::manager::manager(bus, OBJPATH);

    // sd_event object. StateManager wants that this applicatin return '0'
    // always.
    auto r = sd_event_default(&events);
    if (r < 0)
    {
        log<level::ERR>("Failure to create sd_event handler",
                entry("ERROR=%s", strerror(-r)));
        return 0;
    }

    // Create the Timer object
    phosphor::ipmi::Timer timer(events, eventSource,
                phosphor::ipmi::SoftPowerOff::timeoutHandler);

    // Initialize the timer object
    r = timer.initialize();
    if (r < 0)
    {
        log<level::ERR>("Failure initializing the timer object",
                entry("ERROR=%s", strerror(-r)));
        return 0;
    }

    // Attach the bus to sd_event to service user requests
    bus.attach_event(events, SD_EVENT_PRIORITY_NORMAL);

    // Create the SoftPowerOff object.
    phosphor::ipmi::SoftPowerOff powerObj(bus, OBJPATH, timer);

    /** @brief Claim the bus. Delaying it until sending SMS_ATN may result
     *  in a race condition between this available and IPMI trying to send
     *  message as a reponse to ack from host.
     */
    bus.request_name(BUSNAME);

    // The whole purpose of this application is to send SMS_ATTN
    // and watch for the soft power off to go through.
    int64_t resp = powerObj.sendSmsAttn();
    if (resp)
    {
        log<level::ERR>("Failure to send SMS_ATN.",
                entry("ERROR=%s", strerror(resp)));
        return 0;
    }

    // Start the initial timer for host to ack the SMS_ATN
    auto time = duration_cast<microseconds>(
            seconds(IPMI_SMS_ATN_ACK_TIMEOUT_SECS));
    r = powerObj.startTimer(time.count());
    if (r < 0)
    {
        log<level::ERR>("Failure to start the SMS_ATN response timer",
                entry("ERROR=%s", strerror(-r)));
        // This application always needs to return success so that the
        // remaining part of power off can continue
        return 0;
    }

    /** @brief Wait for client requests until this application has processed
     *         at least one successful SoftPowerOff
     */
    while(!powerObj.isCompleted() && !powerObj.isTimerExpired())
    {
        // -1 denotes wait for ever
        r = sd_event_run(events, (uint64_t)-1);
        if (r < 0)
        {
            log<level::ERR>("Failure in processing request",
                    entry("ERROR=%s", strerror(-r)));
        }
    }

    // Log an error if we timed out waiting for host to shutdown
    if(powerObj.isTimerExpired() && (powerObj.getCurrTimer() == phosphor::ipmi
                         ::SoftPowerOff::timerType::HOST_SHUTDOWN_COMPLETE))
    {
        try
        {
            elog<xyz::openbmc_project::Error::SoftOff::Host>(
                    prev_entry<xyz::openbmc_project::Error::SoftOff
                    ::Host::SHUTDOWN_TIME_OUT>());
        }
        catch (elogException<xyz::openbmc_project::Error::SoftOff::Host>& elog)
        {
            commit(elog.name());
        }
    }

    return 0;
}
