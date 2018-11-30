/*
// Copyright (c) 2018 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include "channel_layer.hpp"

#include "channel_mgmt.hpp"

#include <phosphor-logging/log.hpp>

namespace ipmi
{

bool doesDeviceExist(uint8_t chNum)
{
    // TODO: This is not the reliable way to find the device
    // associated with ethernet interface as the channel number to
    // eth association is not done. Need to revisit later
    struct stat fileStat;
    std::string devName("/sys/class/net/eth");
    devName += std::to_string(chNum - 1);

    if (stat(devName.data(), &fileStat) != 0)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "Ethernet device not found");
        return false;
    }

    return true;
}

bool isValidPrivLimit(uint8_t privLimit)
{
    return ((privLimit >= PRIVILEGE_CALLBACK) && (privLimit <= PRIVILEGE_OEM));
}

bool isValidAccessMode(uint8_t accessMode)
{
    return (
        (accessMode >= static_cast<uint8_t>(EChannelAccessMode::disabled)) &&
        (accessMode <= static_cast<uint8_t>(EChannelAccessMode::shared)));
}

bool isValidChannel(uint8_t chNum)
{
    return getChannelConfigObject().isValidChannel(chNum);
}

bool isValidAuthType(uint8_t chNum, const EAuthType& authType)
{
    return getChannelConfigObject().isValidAuthType(chNum, authType);
}

EChannelSessSupported getChannelSessionSupport(uint8_t chNum)
{
    return getChannelConfigObject().getChannelSessionSupport(chNum);
}

int getChannelActiveSessions(uint8_t chNum)
{
    return getChannelConfigObject().getChannelActiveSessions(chNum);
}

ipmi_ret_t ipmiChannelInit()
{
    getChannelConfigObject();
    return IPMI_CC_OK;
}

ipmi_ret_t getChannelInfo(uint8_t chNum, ChannelInfo& chInfo)
{
    return getChannelConfigObject().getChannelInfo(chNum, chInfo);
}

ipmi_ret_t getChannelAccessData(uint8_t chNum, ChannelAccess& chAccessData)
{
    return getChannelConfigObject().getChannelAccessData(chNum, chAccessData);
}

ipmi_ret_t setChannelAccessData(uint8_t chNum,
                                const ChannelAccess& chAccessData,
                                uint8_t setFlag)
{
    return getChannelConfigObject().setChannelAccessData(chNum, chAccessData,
                                                         setFlag);
}

ipmi_ret_t getChannelAccessPersistData(uint8_t chNum,
                                       ChannelAccess& chAccessData)
{
    return getChannelConfigObject().getChannelAccessPersistData(chNum,
                                                                chAccessData);
}

ipmi_ret_t setChannelAccessPersistData(uint8_t chNum,
                                       const ChannelAccess& chAccessData,
                                       uint8_t setFlag)
{
    return getChannelConfigObject().setChannelAccessPersistData(
        chNum, chAccessData, setFlag);
}

ipmi_ret_t getChannelAuthTypeSupported(uint8_t chNum,
                                       uint8_t& authTypeSupported)
{
    return getChannelConfigObject().getChannelAuthTypeSupported(
        chNum, authTypeSupported);
}

ipmi_ret_t getChannelEnabledAuthType(uint8_t chNum, uint8_t priv,
                                     EAuthType& authType)
{
    return getChannelConfigObject().getChannelEnabledAuthType(chNum, priv,
                                                              authType);
}

} // namespace ipmi
