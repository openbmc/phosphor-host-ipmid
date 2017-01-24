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

// Need this to send SMS_ATTN
constexpr auto HOST_IPMI_BUS  = "org.openbmc.HostIpmi";
constexpr auto HOST_IPMI_OBJ  = "/org/openbmc/HostIpmi/1";
constexpr auto HOST_IPMI_INTF = "org.openbmc.HostIpmi";

// Handy alias for a long enough string.
using base = sdbusplus::xyz::openbmc_project::Ipmi::Internal
                                     ::server::SoftPowerOff;

/** @brief Send the SMS_ATN to host if value is set */
bool SoftPowerOff::initiate(bool value)
{
    // If Value is 'true', then set the SMS attention. There is nothing called
    // 'undo SMS_ATTN' and hence nothing to be done for value of 'false'.
    if(!value || (value == base::initiate()))
    {
        return base::initiate();
    }
    auto method = bus.new_method_call(HOST_IPMI_BUS,
                                    HOST_IPMI_OBJ,
                                    HOST_IPMI_INTF,
                                    "setAttention");

    // If there is any exception, would be thrown here.
    bus.call(method);

    // We have done our job
    return base::initiate(value);
}

/** @brief Handles response from Host */
auto SoftPowerOff::responseReceived(HostResponse value) -> HostResponse
{
    // Will be populated as part of using watchdog.
    return base::responseReceived();
}
} // namespace ipmi
} // namespace phosphor
