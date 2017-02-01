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

/** @brief Host Response handler */
auto SoftPowerOff::responseReceived(HostResponse response) -> HostResponse
{
    using namespace std::chrono;
    using namespace phosphor::logging;

    if (response == HostResponse::SoftOffReceived)
    {
        // Need to stop the running timer and then start a new timer of 45
        // minutes expiration time.
        auto time = duration_cast<microseconds>(minutes(45));
        auto r = timer.startTimer(time.count());
        if (r < 0)
        {
            log<level::ERR>("Failure to START the 45 minutes timer",
                    entry("ERROR=%s", strerror(-r)));

            return sdbusplus::xyz::openbmc_project::Ipmi::Internal
                    ::server::SoftPowerOff::responseReceived();
        }
    }
    else if (response == HostResponse::HostShutdown)
    {
        // Disable the timer since Host has sent the hard power off request
        auto r = timer.setTimer(SD_EVENT_OFF);
        if (r < 0)
        {
            log<level::ERR>("Failure to STOP the timer",
                    entry("ERROR=%s", strerror(-r)));

            return sdbusplus::xyz::openbmc_project::Ipmi::Internal
                    ::server::SoftPowerOff::responseReceived();
        }

        // This marks the completion of soft power off sequence.
        completed = true;
    }

    return sdbusplus::xyz::openbmc_project::Ipmi::Internal
              ::server::SoftPowerOff::responseReceived(response);
}

} // namespace ipmi
} // namespace phosphor
