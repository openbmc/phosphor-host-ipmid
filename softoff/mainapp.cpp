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
    auto bus = std::move(sdbusplus::bus::new_default());

    auto objPath = std::string(OBJPATH);

    // Add systemd object manager.
    sdbusplus::server::manager::manager(bus, OBJPATH);

    // Create the SoftPowerOff object.
    // Need to save this else sdbusplus destructor will wipe this off.
    std::vector<std::unique_ptr<phosphor::ipmi::SoftPowerOff>> objVec;

    objVec.emplace_back(std::make_unique<phosphor::ipmi::SoftPowerOff>(
                bus, OBJPATH));

    /** @brief Claim the bus */
    bus.request_name(BUSNAME);

    /** @brief Wait for client requests */
    while(true)
    {
        // Handle dbus message / signals discarding unhandled
        bus.process_discard();
        bus.wait();
    }
    return 0;
}
