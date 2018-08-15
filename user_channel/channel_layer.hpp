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
#include <string>
#include <host-ipmid/ipmid-api.h>

namespace ipmi
{

static constexpr uint8_t maxIpmiChannels = 16;

// TODO: This should be declared in ipmi-api.h
static constexpr uint8_t PRIVILEGE_MAX = PRIVILEGE_OEM + 1;

// IPMI return codes specific to channel
enum ipmi_channel_return_codes
{
    IPMI_CC_ACTION_NOT_SUPPORTED_FOR_CHANNEL = 0x82,
    IPMI_CC_ACCESS_MODE_NOT_SUPPORTED_FOR_CHANEL = 0x83
};

// IPMI Spec: Channel Protocol Type
typedef enum {
    protoNa = 0x00,
    protoIpmbV10 = 0x01,
    protoIcmbV11 = 0x02,
    protoReserved = 0x03,
    protoIpmiSmbus = 0x04,
    protoKcs = 0x05,
    protoSmic = 0x06,
    protoBt10 = 0x07,
    protoBt15 = 0x08,
    protoTMode = 0x09,
    protoOem = 0x1C,
} EChannelProtocolType;

// IPMI Spec: Channel Medium Type
typedef enum {
    mediumReserved = 0x00,
    mediumIpmb = 0x01,
    mediumIcmbV10 = 0x02,
    mediumIcmbV09 = 0x03,
    mediumLan8032 = 0x04,
    mediumSerial = 0x05,
    mediumOtherLan = 0x06,
    mediumPciSmbus = 0x07,
    mediumSmbusV11 = 0x08,
    mediumSmbusV20 = 0x09,
    mediumUsbV1x = 0x0A,
    mediumUsbV2x = 0x0B,
    mediumSystemInterface = 0x0C,
    mediumOem = 0x60,
    mediumUnknown = 0x82,
} EChannelMediumType;

// IPMI Spec: Channel Session Type
typedef enum {
    sessionNone = 0,
    sessionSingle = 1,
    sessionMulti = 2,
    sessionAny = 3,
} EChannelSessSupported;

// IPMI Spec: Channel Access Mode
typedef enum {
    accessDisabled = 0,
    accessPreboot = 1,
    accessAlwaysAvail = 2,
    accessShared = 3,
} EChannelAccessMode;

// IPMI Spec 2.0 : Authentication Types
typedef enum {
    authNone = (1 << 0x0),
    authMD2 = (1 << 0x1),
    authMD5 = (1 << 0x2),
    authReserved = (1 << 0x3),
    authStraightPasswd = (1 << 0x4),
    authOem = (1 << 0x5),
} EAuthType;

// IPMI Spec: Access mode for channel access set/get
typedef enum {
    donotSet = 0x00,
    nvData = 0x01,
    activeData = 0x02,
    reserved1 = 0x03,
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
bool isValidChannel(const uint8_t &chNum);

bool isDeviceExist(const uint8_t &chNum);

bool isValidPrivLimit(const uint8_t &privLimit);

bool isValidAccessMode(const uint8_t &accessMode);

bool isValidAuthType(const uint8_t &chNum, const uint8_t &authType);

EChannelSessSupported getChannelSessionSupport(const uint8_t &chNum);

int getChannelActiveSessions(const uint8_t &chNum);

ipmi_ret_t ipmiChannelInit();

ipmi_ret_t getChannelInfo(const uint8_t &chNum, ChannelInfo &chInfo);

ipmi_ret_t getChannelAccessData(const uint8_t &chNum,
                                ChannelAccess &chAccessData);

ipmi_ret_t setChannelAccessData(const uint8_t &chNum,
                                const ChannelAccess &chAccessData,
                                const uint8_t &setFlag);

ipmi_ret_t getChannelAccessPersistData(const uint8_t &chNum,
                                       ChannelAccess &chAccessData);

ipmi_ret_t setChannelAccessPersistData(const uint8_t &chNum,
                                       const ChannelAccess &chAccessData,
                                       const uint8_t &setFlag);

ipmi_ret_t getChannelAuthTypeSupported(const uint8_t &chNum,
                                       uint8_t &authTypeSupported);

ipmi_ret_t getChannelEnabledAuthType(const uint8_t &chNum, const uint8_t &priv,
                                     uint8_t &authType);

} // namespace ipmi
