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
static constexpr uint8_t selfChNum = 0xE;

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

/** @brief determines valid channel
 *
 *  @param[in] chNum- channel number
 *
 *  @return true if valid, false otherwise
 */
bool isValidChannel(uint8_t chNum);

/** @brief determines whether channel device exist
 *
 *  @param[in] chNum - channel number
 *
 *  @return true if valid, false otherwise
 */
bool doesDeviceExist(uint8_t chNum);

/** @brief determines whether privilege limit is valid
 *
 *  @param[in] privLimit - Privilege limit
 *
 *  @return true if valid, false otherwise
 */
bool isValidPrivLimit(uint8_t privLimit);

/** @brief determines whether access mode  is valid
 *
 *  @param[in] accessMode - Access mode
 *
 *  @return true if valid, false otherwise
 */
bool isValidAccessMode(uint8_t accessMode);

/** @brief determines valid authentication type based on channel number
 *
 *  @param[in] chNum - channel number
 *  @param[in] authType - authentication type
 *
 *  @return true if valid, false otherwise
 */
bool isValidAuthType(uint8_t chNum, EAuthType authType);

/** @brief determines supported session type of a channel
 *
 *  @param[in] chNum - channel number
 *
 *  @return EChannelSessSupported - supported session type
 */
EChannelSessSupported getChannelSessionSupport(uint8_t chNum);

/** @brief determines number of active sessions on a channel
 *
 *  @param[in] chNum - channel number
 *
 *  @return numer of active sessions
 */
int getChannelActiveSessions(uint8_t chNum);

/** @brief initializes channel management
 *
 *  @return IPMI_CC_OK for success, others for failure.
 */
ipmi_ret_t ipmiChannelInit();

/** @brief provides channel info details
 *
 *  @param[in] chNum - channel number
 *  @param[out] chInfo - channel info details
 *
 *  @return IPMI_CC_OK for success, others for failure.
 */
ipmi_ret_t getChannelInfo(uint8_t chNum, ChannelInfo& chInfo);

/** @brief provides channel access data
 *
 *  @param[in] chNum - channel number
 *  @param[out] chAccessData -channel access data
 *
 *  @return IPMI_CC_OK for success, others for failure.
 */
ipmi_ret_t getChannelAccessData(uint8_t chNum, ChannelAccess& chAccessData);

/** @brief to set channel access data
 *
 *  @param[in] chNum - channel number
 *  @param[in] chAccessData - channel access data
 *  @param[in] setFlag - flag to indicate updatable fields
 *
 *  @return IPMI_CC_OK for success, others for failure.
 */
ipmi_ret_t setChannelAccessData(uint8_t chNum,
                                const ChannelAccess& chAccessData,
                                uint8_t setFlag);

/** @brief to get channel access data persistent data
 *
 *  @param[in] chNum - channel number
 *  @param[out] chAccessData - channel access data
 *
 *  @return IPMI_CC_OK for success, others for failure.
 */
ipmi_ret_t getChannelAccessPersistData(uint8_t chNum,
                                       ChannelAccess& chAccessData);

/** @brief to set channel access data persistent data
 *
 *  @param[in] chNum - channel number
 *  @param[in] chAccessData - channel access data
 *  @param[in] setFlag - flag to indicate updatable fields
 *
 *  @return IPMI_CC_OK for success, others for failure.
 */
ipmi_ret_t setChannelAccessPersistData(uint8_t chNum,
                                       const ChannelAccess& chAccessData,
                                       uint8_t setFlag);

/** @brief provides supported authentication type for the channel
 *
 *  @param[in] chNum - channel number
 *  @param[out] authTypeSupported - supported authentication type
 *
 *  @return IPMI_CC_OK for success, others for failure.
 */
ipmi_ret_t getChannelAuthTypeSupported(uint8_t chNum,
                                       uint8_t& authTypeSupported);

/** @brief provides enabled authentication type for the channel
 *
 *  @param[in] chNum - channel number
 *  @param[in] priv - privilege
 *  @param[out] authType - enabled authentication type
 *
 *  @return IPMI_CC_OK for success, others for failure.
 */
ipmi_ret_t getChannelEnabledAuthType(uint8_t chNum, uint8_t priv,
                                     EAuthType& authType);

} // namespace ipmi
