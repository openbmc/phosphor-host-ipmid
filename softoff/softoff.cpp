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
#include <log.hpp>
#include "softoff.hpp"
namespace phosphor
{
namespace ipmi
{

/** @brief Chassis dbus constructs to do a hard power off */
// TODO : Need to move over to using mapper to get service name
static constexpr auto CHASSIS_SERVICE = "xyz.openbmc_project.State.Chassis";
static constexpr auto CHASSIS_OBJ     = "/xyz/openbmc_project/state/chassis0";
static constexpr auto CHASSIS_INTF    = "xyz.openbmc_project.State.Chassis";

// Property and the desired value
static constexpr auto CHASSIS_OFF   = "xyz.openbmc_project.State.Chassis.\
                                       Transition.Off";
static constexpr auto PROPERTY_INTF = "org.freedesktop.DBus.Properties";

/** @brief Send the SMS_ATN to host if value is set */
int64_t SoftPowerOff::sendSmsAttn()
{
    // Response from BT
    int64_t btResp {};

    auto method = bus.new_method_call(HOST_IPMI_BUS,
                                      HOST_IPMI_OBJ,
                                      HOST_IPMI_INTF,
                                      "setAttention");

    // If there is any exception, would be thrown here.
    auto reply = bus.call(method);

    // BT returns '0' on success and bus_error on failure.
    // Catching the rc anyway.
    reply.read(btResp);

    return btResp;
}

/** @brief callback handler on timeout */
int SoftPowerOff::timeoutHandler(sd_event_source* eventSource,
                                 uint64_t usec, void* userData)
{
    using namespace phosphor::logging;

    log<level::INFO>("Watchdog timer expired !. Forcing Hard power off");

    // Get the handle to this object that was bound during registration
    auto timer = static_cast<Timer*>(userData);

    // The only thing that is to be done here is to make a call
    // to Chassis object to do Hard Power Off.
    auto method = timer->bus.new_method_call(CHASSIS_SERVICE,
                                             CHASSIS_OBJ,
                                             PROPERTY_INTF,
                                             "Set");
    // Fill the Interface, property name and its value.
    method.append(CHASSIS_INTF,
                  "RequestedPowerTransition",
                  CHASSIS_OFF);

    // Set the property.
    timer->bus.call(method);

    // The timer is now considerd 'expired` !!
    timer->expired = true;

    return 0;
}

} // namespace ipmi
} // namespace phosphor
