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
#include "config.h"

namespace phosphor
{
namespace ipmi
{

/** @brief Sends the SMS_ATN to host if value is set */
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

    // Get the handle to this object that was bound during registration
    auto timer = static_cast<Timer*>(userData);

    log<level::ERR>("SoftOff Watchdog timer expired");

    // The timer is now considerd 'expired` !!
    timer->expired = true;

    // Nothing more needs to be done here.
    return 0;
}

/** @brief Host Response handler */
auto SoftPowerOff::responseReceived(HostResponse response) -> HostResponse
{
    using namespace std::chrono;
    using namespace phosphor::logging;

    if (response == HostResponse::SoftOffReceived)
    {
        // Need to stop the running timer and then start a new timer
        // Default wait time is 45 minutes
        auto time = duration_cast<microseconds>(
                seconds(IPMI_HOST_SHUTDOWN_COMPLETE_TIMEOUT_SECS));
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
        // Disable the timer since Host has quiesced and we are
        // done with soft power off part
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
