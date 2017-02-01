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
#include <phosphor-logging/log.hpp>
#include "softoff.hpp"
namespace phosphor
{
namespace ipmi
{

/** @brief Send the SMS_ATN to host if value is set */
void SoftPowerOff::sendSMSAttn()
{
    auto method = bus.new_method_call(HOST_IPMI_BUS,
                                      HOST_IPMI_OBJ,
                                      HOST_IPMI_INTF,
                                      "setAttention");

    // If there is any exception, would be thrown here.
    // BT returns '0' on success and bus_error on failure.
    bus.call_noreply(method);

    return;
}

/** @brief callback handler on timeout */
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

} // namespace ipmi
} // namespace phosphor
