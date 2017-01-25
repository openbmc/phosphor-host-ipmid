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
#include "softoff.hpp"
namespace phosphor
{
namespace ipmi
{

// Initialize the static member
bool SoftPowerOff::completed = false;

// Need this to send SMS_ATTN
// TODO : Switch over to using mapper service in a different patch
constexpr auto HOST_IPMI_BUS  = "org.openbmc.HostIpmi";
constexpr auto HOST_IPMI_OBJ  = "/org/openbmc/HostIpmi/1";
constexpr auto HOST_IPMI_INTF = "org.openbmc.HostIpmi";

/** @brief Send the SMS_ATN to host if value is set */
void SoftPowerOff::sendSmsAttn()
{
    auto method = bus.new_method_call(HOST_IPMI_BUS,
                                      HOST_IPMI_OBJ,
                                      HOST_IPMI_INTF,
                                      "setAttention");

    // If there is any exception, would be thrown here.
    bus.call(method);
}

/** @brief Gets called into on receiving watchdog 'Timeout' signal */
int SoftPowerOff::handleTimeOut(sd_bus_message* msg, void* userData,
                                sd_bus_error* retError)
{
    // Get the handle to this object that was bound during registration
    auto thisObject = static_cast<SoftPowerOff*>(userData);

    // The only thing that is to be done here is to make a call to Chassis
    // object to do Hard Power Off.
    auto method = thisObject->bus.new_method_call(wdog::CHASSIS_SERVICE,
                                                  wdog::CHASSIS_OBJ,
                                                  wdog::PROPERTY_INTF,
                                                  "Set");

    // Fill the Interface, property name and its value.
    method.append(wdog::CHASSIS_INTF,
                  "RequestedPowerTransition",
                  wdog::CHASSIS_OFF);

    // Set the property.
    thisObject->bus.call(method);

    // This marks the END of life for this application.
    completed = true;

    return 0;
}

} // namespace ipmi
} // namespace phosphor
