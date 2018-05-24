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
#include <cstdint>

namespace ipmi
{

static constexpr uint8_t maxIpmiChannels = 16;

// IPMI commands for channel command NETFN:APP.
enum ipmi_netfn_channel_cmds
{
    IPMI_CMD_SET_CHANNEL_ACCESS = 0x40,
    IPMI_CMD_GET_CHANNEL_ACCESS = 0x41,
    IPMI_CMD_GET_CHANNEL_INFO = 0x42,
};

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

} // namespace ipmi
