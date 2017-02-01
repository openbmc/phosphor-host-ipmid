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

/** @brief Host Response handler */
auto SoftPowerOff::responseReceived(HostResponse response) -> HostResponse
{
    using namespace std::chrono;
    using namespace phosphor::logging;

    if (response == HostResponse::SoftOffReceived)
    {
        // Need to stop the running timer and then start a new timer of 45
        // minutes expiration time.
        auto time = duration_cast<nanoseconds>(minutes(45));
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
        auto r = timer.armTimer(SD_EVENT_OFF);
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
