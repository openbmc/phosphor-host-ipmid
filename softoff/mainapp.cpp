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
#include <iostream>
#include <string.h>
#include <systemd/sd-event.h>
#include <log.hpp>
#include "softoff.hpp"
#include "timer.hpp"
#include "config.h"

using namespace phosphor::logging;

int main(int argc, char** argv)
{
    // systemd event handler
    sd_event* events = nullptr;

    // Get a handle to system dbus.
    auto bus = sdbusplus::bus::new_default();

    // Add systemd object manager.
    sdbusplus::server::manager::manager(bus, OBJPATH);

    // sd_event object
    auto r = sd_event_default(&events);
    if (r < 0)
    {
        log<level::ERR>("Failure to create sd_event handler",
                entry("ERROR=%s", strerror(-r)));
        return -1;
    }

    // Create the Timer object
    phosphor::ipmi::Timer timer(bus, events);

    // Create the SoftPowerOff object.
    phosphor::ipmi::SoftPowerOff powerObj(bus, OBJPATH, timer);

    // The whole purpose of this application is to send SMS_ATTN
    // and watch for the soft power off to go through.
    powerObj.sendSmsAttn();

    /** @brief Claim the bus */
    bus.request_name(BUSNAME);

    /** @brief Wait for client requests until this application has processed
     *         atleast one successful SoftPowerOff
     */
    while(!powerObj.isCompleted() && !timer.isExpired())
    {
        // -1 denotes wait for ever
        r = sd_event_run(events, (uint64_t)-1);
        if (r < 0)
        {
            log<level::ERR>("Failure in processing request",
                    entry("ERROR=%s", strerror(-r)));
            return -1;
        }
    }
    return 0;
}
