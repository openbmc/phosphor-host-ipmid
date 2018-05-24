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
#pragma once
#include <host-ipmid/ipmid-api.h>

#include <string>

namespace ipmi
{

static constexpr uint8_t maxIpmiChannels = 16;

// IPMI return codes specific to channel
enum ipmi_channel_return_codes
{
    IPMI_CC_ACTION_NOT_SUPPORTED_FOR_CHANNEL = 0x82,
    IPMI_CC_ACCESS_MODE_NOT_SUPPORTED_FOR_CHANEL = 0x83
};

// IPMI Spec: Channel Protocol Type
enum class EChannelProtocolType : uint8_t
{
    na = 0x00,
    ipmbV10 = 0x01,
    icmbV11 = 0x02,
    reserved = 0x03,
    ipmiSmbus = 0x04,
    kcs = 0x05,
    smic = 0x06,
    bt10 = 0x07,
    bt15 = 0x08,
    tMode = 0x09,
    oem = 0x1C,
};

// IPMI Spec: Channel Medium Type
enum class EChannelMediumType : uint8_t
{
    reserved = 0x00,
    ipmb = 0x01,
    icmbV10 = 0x02,
    icmbV09 = 0x03,
    lan8032 = 0x04,
    serial = 0x05,
    otherLan = 0x06,
    pciSmbus = 0x07,
    smbusV11 = 0x08,
    smbusV20 = 0x09,
    usbV1x = 0x0A,
    usbV2x = 0x0B,
    systemInterface = 0x0C,
    oem = 0x60,
    unknown = 0x82,
};

// IPMI Spec: Channel Session Type
enum class EChannelSessSupported : uint8_t
{
    none = 0,
    single = 1,
    multi = 2,
    any = 3,
};

// IPMI Spec: Channel Access Mode
enum class EChannelAccessMode : uint8_t
{
    disabled = 0,
    preboot = 1,
    alwaysAvail = 2,
    shared = 3,
};

// IPMI Spec 2.0 : Authentication Types
enum class EAuthType : uint8_t
{
    none = (1 << 0x0),
    md2 = (1 << 0x1),
    md5 = (1 << 0x2),
    reserved = (1 << 0x3),
    straightPasswd = (1 << 0x4),
    oem = (1 << 0x5),
};

// IPMI Spec: Access mode for channel access set/get
typedef enum
{
    doNotSet = 0x00,
    nvData = 0x01,
    activeData = 0x02,
    reserved = 0x03,
} EChannelActionType;

enum AccessSetFlag
{
    setAccessMode = (1 << 0),
    setUserAuthEnabled = (1 << 1),
    setMsgAuthEnabled = (1 << 2),
    setAlertingEnabled = (1 << 3),
    setPrivLimit = (1 << 4),
};

// Struct to store channel access data
struct ChannelAccess
{
    uint8_t accessMode;
    bool userAuthDisabled;
    bool perMsgAuthDisabled;
    bool alertingDisabled;
    uint8_t privLimit;
};

// Struct store channel info data
struct ChannelInfo
{
    uint8_t mediumType;
    uint8_t protocolType;
    uint8_t sessionSupported;
    bool isIpmi; // Is session IPMI
    // This is used in Get LAN Configuration parameter.
    // This holds the supported AuthTypes for a given channel.
    uint8_t authTypeSupported;
};

/** @brief determines valid userId
 *
 *  @param[in] user id
 *
 *  @return true if valid, false otherwise
 */
bool isValidChannel(const uint8_t& chNum);

bool doesDeviceExist(const uint8_t& chNum);

bool isValidPrivLimit(const uint8_t& privLimit);

bool isValidAccessMode(const uint8_t& accessMode);

bool isValidAuthType(const uint8_t& chNum, const uint8_t& authType);

EChannelSessSupported getChannelSessionSupport(const uint8_t& chNum);

int getChannelActiveSessions(const uint8_t& chNum);

ipmi_ret_t ipmiChannelInit();

ipmi_ret_t getChannelInfo(const uint8_t& chNum, ChannelInfo& chInfo);

ipmi_ret_t getChannelAccessData(const uint8_t& chNum,
                                ChannelAccess& chAccessData);

ipmi_ret_t setChannelAccessData(const uint8_t& chNum,
                                const ChannelAccess& chAccessData,
                                const uint8_t& setFlag);

ipmi_ret_t getChannelAccessPersistData(const uint8_t& chNum,
                                       ChannelAccess& chAccessData);

ipmi_ret_t setChannelAccessPersistData(const uint8_t& chNum,
                                       const ChannelAccess& chAccessData,
                                       const uint8_t& setFlag);

ipmi_ret_t getChannelAuthTypeSupported(const uint8_t& chNum,
                                       uint8_t& authTypeSupported);

ipmi_ret_t getChannelEnabledAuthType(const uint8_t& chNum, const uint8_t& priv,
                                     uint8_t& authType);

} // namespace ipmi
