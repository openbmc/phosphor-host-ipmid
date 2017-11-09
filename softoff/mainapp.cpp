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
#include <systemd/sd-event.h>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <xyz/openbmc_project/State/Host/error.hpp>
#include "softoff.hpp"
#include "config.h"
#include "timer.hpp"

// Return -1 on any errors to ensure we follow the calling targets OnFailure=
// path
int main(int argc, char** argv)
{
    using namespace phosphor::logging;

    // systemd event handler
    sd_event* events = nullptr;

    // Get a handle to system dbus.
    auto bus = sdbusplus::bus::new_default();

    // Add systemd object manager.
    sdbusplus::server::manager::manager(bus, SOFTOFF_OBJPATH);

    // sd_event object
    auto r = sd_event_default(&events);
    if (r < 0)
    {
        log<level::ERR>("Failure to create sd_event handler",
                entry("ERRNO=0x%X", -r));
        return -1;
    }

    // Attach the bus to sd_event to service user requests
    bus.attach_event(events, SD_EVENT_PRIORITY_NORMAL);

    // Claim the bus. Delaying it until sending SMS_ATN may result
    // in a race condition between this available and IPMI trying to send
    // message as a response to ack from host.
    bus.request_name(SOFTOFF_BUSNAME);

    // Create the SoftPowerOff object.
    phosphor::ipmi::SoftPowerOff powerObj(bus, events, SOFTOFF_OBJPATH);

    // Wait for client requests until this application has processed
    // at least one successful SoftPowerOff or we timed out
    while(!powerObj.isCompleted() && !powerObj.isTimerExpired())
    {
        // -1 denotes wait for ever
        r = sd_event_run(events, (uint64_t)-1);
        if (r < 0)
        {
            log<level::ERR>("Failure in processing request",
                    entry("ERRNO=0x%X", -r));
            return -1;
        }
    }

    // Log an error if we timed out after getting Ack for SMS_ATN and before
    // getting the Host Shutdown response
    if(powerObj.isTimerExpired() && (powerObj.responseReceived() ==
            phosphor::ipmi::Base::SoftPowerOff::HostResponse::SoftOffReceived))
    {
        using error =
            sdbusplus::xyz::openbmc_project::State::Host::Error::SoftOffTimeout;
        using errorMetadata = xyz::openbmc_project::State::Host::SoftOffTimeout;
        report<error>(prev_entry<errorMetadata::TIMEOUT_IN_MSEC>());
        return -1;
    }

    // Cleanup the event handler
    events = sd_event_unref(events);

    return 0;
}
