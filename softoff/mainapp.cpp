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
#include "softoff.hpp"
#include "config.h"
#include "timer.hpp"

int main(int argc, char** argv)
{
    using namespace phosphor::logging;
    using namespace std::chrono;

    // systemd event handler
    sd_event* events = nullptr;

    // Get a handle to system dbus.
    auto bus = sdbusplus::bus::new_default();

    // Add systemd object manager.
    sdbusplus::server::manager::manager(bus, SOFTOFF_OBJPATH);

    // sd_event object. StateManager wants that this applicatin return '0'
    // always.
    auto r = sd_event_default(&events);
    if (r < 0)
    {
        log<level::ERR>("Failure to create sd_event handler",
                entry("ERROR=%s", strerror(-r)));
        return 0;
    }

    // Attach the bus to sd_event to service user requests
    bus.attach_event(events, SD_EVENT_PRIORITY_NORMAL);

    // Claim the bus. Delaying it until sending SMS_ATN may result
    // in a race condition between this available and IPMI trying to send
    // message as a reponse to ack from host.
    bus.request_name(SOFTOFF_BUSNAME);

    // Create the SoftPowerOff object.
    phosphor::ipmi::SoftPowerOff powerObj(bus, events, SOFTOFF_OBJPATH);

    // By now, SMS attention would have been sent as part of the powerObj
    // construction.
    // Start the initial timer for host to ack the SMS_ATN
    auto time = duration_cast<microseconds>(
            seconds(IPMI_SMS_ATN_ACK_TIMEOUT_SECS));
    r = powerObj.startTimer(time);
    if (r < 0)
    {
        log<level::ERR>("Failure to start the SMS_ATN response timer",
                entry("ERROR=%s", strerror(-r)));
        return 0;
    }

    // Wait for client requests until this application has processed
    // at least one successful SoftPowerOff or we timed out
    while(!powerObj.isCompleted() && !powerObj.isTimerExpired())
    {
        // -1 denotes wait for ever
        r = sd_event_run(events, (uint64_t)-1);
        if (r < 0)
        {
            log<level::ERR>("Failure in processing request",
                    entry("ERROR=%s", strerror(-r)));
            break;
        }
    }

    // Log an error if we timed out after getting Ack for SMS_ATN and before
    // getting the Host Shutdown response
    if(powerObj.isTimerExpired() && (powerObj.responseReceived() ==
             phosphor::ipmi::Base::SoftPowerOff::HostResponse::SoftOffReceived))
    {
        try
        {
            elog<xyz::openbmc_project::State::Host::SoftOffTimeout>(
                    prev_entry<xyz::openbmc_project::State::Host::SoftOffTimeout::
                    TIMEOUT_IN_MSEC>());
        }
        catch (elogException<xyz::openbmc_project::State::Host::SoftOffTimeout>& elog)
        {
            commit(elog.name());
        }
    }

    return 0;
}
