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
#include <phosphor-logging/log.hpp>
#include "softoff.hpp"
#include "config.h"

namespace phosphor
{
namespace ipmi
{

// Sends the SMS_ATN to host if value is set
void SoftPowerOff::sendSMSAttn()
{
    using namespace std::chrono;

    auto method = bus.new_method_call(HOST_IPMI_BUS,
                                      HOST_IPMI_OBJ,
                                      HOST_IPMI_INTF,
                                      "setAttention");

    // If there is any exception, would be thrown here.
    // BT returns '0' on success and bus_error on failure.
    bus.call_noreply(method);

    return;
}

// Callback handler on timeout
int SoftPowerOff::timeoutHandler(sd_event_source* eventSource,
                                 uint64_t usec, void* userData)
{
    using namespace phosphor::logging;

    // Get the handle to this object that was bound during registration
    auto softOff = static_cast<SoftPowerOff*>(userData);

    log<level::ERR>("SoftOff Watchdog timer expired");

    // The timer is now considerd 'expired` !!
    softOff->timer.expired = true;

    // Nothing more needs to be done here.
    return 0;
}

// Starts a timer
int SoftPowerOff::startTimer(const std::chrono::microseconds& usec)
{
    return timer.startTimer(usec);
}

// Host Response handler
auto SoftPowerOff::responseReceived(HostResponse response) -> HostResponse
{
    using namespace std::chrono;
    using namespace phosphor::logging;

    if (response == HostResponse::SoftOffReceived)
    {
        // Need to stop the running timer and then start a new timer
        auto time = duration_cast<microseconds>(
                seconds(IPMI_HOST_SHUTDOWN_COMPLETE_TIMEOUT_SECS));
        auto r = startTimer(time);
        if (r < 0)
        {
            log<level::ERR>("Failure to start Host shutdown wait timer",
                    entry("ERROR=%s", strerror(-r)));
        }
        else
        {
            log<level::INFO>("Timer started waiting for host to shutdown",
                    entry("SHUTDOWN_TIME_OUT_SECONDS=%d",
                        IPMI_HOST_SHUTDOWN_COMPLETE_TIMEOUT_SECS));
        }
    }
    else if (response == HostResponse::HostShutdown)
    {
        // Disable the timer since Host has quiesced and we are
        // done with soft power off part
        auto r = timer.setTimer(SD_EVENT_OFF);
        if (r < 0)
        {
            log<level::ERR>("Failure to STOP the timer",
                    entry("ERROR=%s", strerror(-r)));
        }

        // This marks the completion of soft power off sequence.
        completed = true;
    }

    return sdbusplus::xyz::openbmc_project::Ipmi::Internal
              ::server::SoftPowerOff::responseReceived(response);
}

} // namespace ipmi
} // namespace phosphor
