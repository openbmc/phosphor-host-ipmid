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
#include "softoff.hpp"
#include "config.h"

int main(int argc, char** argv)
{
    // Get a handle to system dbus.
    auto bus = sdbusplus::bus::new_default();

    // Add systemd object manager.
    sdbusplus::server::manager::manager(bus, OBJPATH);

    // Create the SoftPowerOff object.
    phosphor::ipmi::SoftPowerOff obj(bus, OBJPATH);

    /** @brief Claim the bus */
    bus.request_name(BUSNAME);

    /** @brief Wait for client requests until this application has processed
     *         atleast one successful SoftPowerOff
     */
    while(!phosphor::ipmi::SoftPowerOff::completed)
    {
        // Handle dbus message / signals discarding unhandled
        bus.process_discard();
        bus.wait();
    }
    return 0;
}
