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

#include "channelcommands.hpp"

#include "apphandler.hpp"
#include "channel_layer.hpp"

#include <ipmid/api.hpp>
#include <phosphor-logging/log.hpp>
#include <regex>

using namespace phosphor::logging;

namespace ipmi
{

/** @struct GetChannelPayloadSupportReq
 *
 *  Structure for get channel payload support command request (refer spec
 *  sec 24.8)
 */
struct GetChannelPayloadSupportReq
{
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t chNum : 4;
    uint8_t reserved : 4;
#endif
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t reserved : 4;
    uint8_t chNum : 4;
#endif
} __attribute__((packed));

/** @struct GetChannelPayloadSupportResp
 *
 *  Structure for get channel payload support command response (refer spec
 *  sec 24.8)
 */
struct GetChannelPayloadSupportResp
{
    uint8_t stdPayloadType[2];
    uint8_t sessSetupPayloadType[2];
    uint8_t OEMPayloadType[2];
    uint8_t reserved[2];
} __attribute__((packed));

/** @brief implements the set channel access command
 *  @ param ctx - context pointer
 *  @ param channel - channel number
 *  @ param reserved - skip 4 bits
 *  @ param accessMode - access mode for IPMI messaging
 *  @ param usrAuth - user level authentication (enable/disable)
 *  @ param msgAuth - per message authentication (enable/disable)
 *  @ param alertDisabled - PEF alerting (enable/disable)
 *  @ param chanAccess - channel access
 *  @ param channelPrivLimit - channel privilege limit
 *  @ param reserved - skip 3 bits
 *  @ param channelPrivMode - channel priviledge mode
 *
 *  @ returns IPMI completion code
 **/
RspType<> ipmiSetChannelAccess(Context::ptr ctx, uint4_t channel,
                               uint4_t reserved1, uint3_t accessMode,
                               bool usrAuth, bool msgAuth, bool alertDisabled,
                               uint2_t chanAccess, uint4_t channelPrivLimit,
                               uint2_t reserved2, uint2_t channelPrivMode)
{
    const uint8_t chNum =
        convertCurrentChannelNum(static_cast<uint8_t>(channel), ctx->channel);

    if (!isValidChannel(chNum) || reserved1 != 0 || reserved2 != 0)
    {
        log<level::DEBUG>("Set channel access - Invalid field in request");
        return responseInvalidFieldRequest();
    }

    if (getChannelSessionSupport(chNum) == EChannelSessSupported::none)
    {
        log<level::DEBUG>("Set channel access - No support on channel");
        return responseInvalidFieldRequest();
    }

    ChannelAccess chActData;
    ChannelAccess chNVData;
    uint8_t setActFlag = 0;
    uint8_t setNVFlag = 0;
    Cc compCode;

    // cannot static cast directly from uint2_t to enum; must go via int
    uint8_t channelAccessAction = static_cast<uint8_t>(chanAccess);
    switch (static_cast<EChannelActionType>(channelAccessAction))
    {
        case doNotSet:
            break;
        case nvData:
            chNVData.accessMode = static_cast<uint8_t>(accessMode);
            chNVData.userAuthDisabled = usrAuth;
            chNVData.perMsgAuthDisabled = msgAuth;
            chNVData.alertingDisabled = alertDisabled;
            setNVFlag |= (setAccessMode | setUserAuthEnabled |
                          setMsgAuthEnabled | setAlertingEnabled);
            break;

        case activeData:
            chActData.accessMode = static_cast<uint8_t>(accessMode);
            chActData.userAuthDisabled = usrAuth;
            chActData.perMsgAuthDisabled = msgAuth;
            chActData.alertingDisabled = alertDisabled;
            setActFlag |= (setAccessMode | setUserAuthEnabled |
                           setMsgAuthEnabled | setAlertingEnabled);
            break;

        case reserved:
        default:
            log<level::DEBUG>("Set channel access - Invalid access set mode");
            return responseInvalidFieldRequest();
    }

    // cannot static cast directly from uint2_t to enum; must go via int
    uint8_t channelPrivAction = static_cast<uint8_t>(channelPrivMode);
    switch (static_cast<EChannelActionType>(channelPrivAction))
    {
        case doNotSet:
            break;
        case nvData:
            chNVData.privLimit = static_cast<uint8_t>(channelPrivLimit);
            setNVFlag |= setPrivLimit;
            break;
        case activeData:
            chActData.privLimit = static_cast<uint8_t>(channelPrivLimit);

            setActFlag |= setPrivLimit;
            break;
        case reserved:
        default:
            log<level::DEBUG>("Set channel access - Invalid access priv mode");
            return responseInvalidFieldRequest();
    }

    if (setNVFlag != 0)
    {
        compCode = setChannelAccessPersistData(chNum, chNVData, setNVFlag);
        if (compCode != IPMI_CC_OK)
        {
            log<level::DEBUG>("Set channel access - Failed to set access data");
            return response(compCode);
        }
    }

    if (setActFlag != 0)
    {
        compCode = setChannelAccessData(chNum, chActData, setActFlag);
        if (compCode != IPMI_CC_OK)
        {
            log<level::DEBUG>("Set channel access - Failed to set access data");
            return response(compCode);
        }
    }

    return responseSuccess();
}

/** @brief implements the get channel access command
 *  @ param ctx - context pointer
 *  @ param channel - channel number
 *  @ param reserved1 - skip 4 bits
 *  @ param reserved2 - skip 6 bits
 *  @ param accessMode - get access mode
 *
 *  @returns ipmi completion code plus response data
 *  - accessMode - get access mode
 *  - usrAuthDisabled - user level authentication status
 *  - msgAuthDisabled - message mevel authentication status
 *  - alertDisabled - alerting status
 *  - reserved - skip 2 bits
 *  - privLimit - channel privilege limit
 *  - reserved - skip 4 bits
 * */
ipmi ::RspType<uint3_t, // access mode,
               bool,    // user authentication status,
               bool,    // message authentication status,
               bool,    // alerting status,
               uint2_t, // reserved,

               uint4_t, // channel privilege,
               uint4_t  // reserved
               >
    ipmiGetChannelAccess(Context::ptr ctx, uint4_t channel, uint4_t reserved1,
                         uint6_t reserved2, uint2_t accessSetMode)
{
    const uint8_t chNum =
        convertCurrentChannelNum(static_cast<uint8_t>(channel), ctx->channel);

    if (!isValidChannel(chNum) || reserved1 != 0 || reserved2 != 0)
    {
        log<level::DEBUG>("Get channel access - Invalid field in request");
        return responseInvalidFieldRequest();
    }

    if ((accessSetMode == doNotSet) || (accessSetMode == reserved))
    {
        log<level::DEBUG>("Get channel access - Invalid Access mode");
        return responseInvalidFieldRequest();
    }

    if (getChannelSessionSupport(chNum) == EChannelSessSupported::none)
    {
        log<level::DEBUG>("Get channel access - No support on channel");
        return response(IPMI_CC_ACTION_NOT_SUPPORTED_FOR_CHANNEL);
    }

    ChannelAccess chAccess;

    Cc compCode;

    if (accessSetMode == nvData)
    {
        compCode = getChannelAccessPersistData(chNum, chAccess);
    }
    else if (accessSetMode == activeData)
    {
        compCode = getChannelAccessData(chNum, chAccess);
    }

    if (compCode != IPMI_CC_OK)
    {
        return response(compCode);
    }

    constexpr uint2_t reservedOut1 = 0;
    constexpr uint4_t reservedOut2 = 0;

    return responseSuccess(
        static_cast<uint3_t>(chAccess.accessMode), chAccess.userAuthDisabled,
        chAccess.perMsgAuthDisabled, chAccess.alertingDisabled, reservedOut1,
        static_cast<uint4_t>(chAccess.privLimit), reservedOut2);
}

/** @brief implements the get channel info command
 *  @ param ctx - context pointer
 *  @ param channel - channel number
 *  @ param reserved - skip 4 bits
 *
 *  @returns ipmi completion code plus response data
 *  - chNum - the channel number for this request
 *  - mediumType - see Table 6-3, Channel Medium Type Numbers
 *  - protocolType - Table 6-2, Channel Protocol Type Numbers
 *  - activeSessionCount - number of active sessions
 *  - sessionType - channel support for sessions
 *  - vendorId - vendor for this channel protocol (IPMI - 7154)
 *  - auxChInfo - auxiliary info for channel
 * */
RspType<uint4_t,  // chNum
        uint4_t,  // reserved
        uint7_t,  // mediumType
        bool,     // reserved
        uint5_t,  // protocolType
        uint3_t,  // reserved
        uint6_t,  // activeSessionCount
        uint2_t,  // sessionType
        uint24_t, // Vendor IANA
        uint16_t  // aux info
        >
    ipmiGetChannelInfo(Context::ptr ctx, uint4_t channel, uint4_t reserved)
{
    uint8_t chNum =
        convertCurrentChannelNum(static_cast<uint8_t>(channel), ctx->channel);
    if (!isValidChannel(chNum) || reserved)
    {
        log<level::DEBUG>("Get channel access - Invalid field in request");
        return responseInvalidFieldRequest();
    }

    ChannelInfo chInfo;
    Cc compCode = getChannelInfo(chNum, chInfo);
    if (compCode != ccSuccess)
    {
        log<level::ERR>("Failed to get channel info",
                        entry("CHANNEL=%x", chNum),
                        entry("ERRNO=%x", compCode));
        return response(compCode);
    }

    constexpr uint4_t reserved1 = 0;
    constexpr bool reserved2 = false;
    constexpr uint3_t reserved3 = 0;
    uint8_t mediumType = chInfo.mediumType;
    uint8_t protocolType = chInfo.protocolType;
    uint2_t sessionType = chInfo.sessionSupported;
    uint6_t activeSessionCount = getChannelActiveSessions(chNum);
    // IPMI Spec: The IPMI Enterprise Number is: 7154 (decimal)
    constexpr uint24_t vendorId = 7154;
    constexpr uint16_t auxChInfo = 0;

    return responseSuccess(chNum, reserved1, mediumType, reserved2,
                           protocolType, reserved3, activeSessionCount,
                           sessionType, vendorId, auxChInfo);
}

ipmi_ret_t ipmiGetChannelPayloadSupport(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                        ipmi_request_t request,
                                        ipmi_response_t response,
                                        ipmi_data_len_t data_len,
                                        ipmi_context_t context)
{
    const auto req = static_cast<GetChannelPayloadSupportReq*>(request);
    size_t reqLength = *data_len;

    *data_len = 0;

    if (reqLength != sizeof(*req))
    {
        log<level::DEBUG>("Get channel payload - Invalid Length");
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    uint8_t chNum = convertCurrentChannelNum(req->chNum);
    if (!isValidChannel(chNum) || req->reserved != 0)
    {
        log<level::DEBUG>("Get channel payload - Invalid field in request");
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    // Not supported on sessionless channels.
    if (EChannelSessSupported::none == getChannelSessionSupport(chNum))
    {
        log<level::DEBUG>("Get channel payload - Sessionless Channel");
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    // Session support is available in active LAN channels.
    if ((EChannelSessSupported::none != getChannelSessionSupport(chNum)) &&
        (!(doesDeviceExist(chNum))))
    {
        log<level::DEBUG>("Get channel payload - Device not exist");
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    auto resp = static_cast<GetChannelPayloadSupportResp*>(response);

    std::fill(reinterpret_cast<uint8_t*>(resp),
              reinterpret_cast<uint8_t*>(resp) + sizeof(*resp), 0);

    // TODO: Hard coding for now.
    // Mapping PayloadTypes to 'GetChannelPayloadSupportResp' fields:
    // --------------------------------------------------------------
    // Mask all except least 3 significant bits to get a value in the range of
    // 0-7. This value maps to the bit position of given payload type in 'resp'
    // fields.

    static constexpr uint8_t payloadByteMask = 0x07;
    static constexpr uint8_t stdPayloadTypeIPMI =
        1 << (static_cast<uint8_t>(PayloadType::IPMI) & payloadByteMask);
    static constexpr uint8_t stdPayloadTypeSOL =
        1 << (static_cast<uint8_t>(PayloadType::SOL) & payloadByteMask);

    static constexpr uint8_t sessPayloadTypeOpenReq =
        1 << (static_cast<uint8_t>(PayloadType::OPEN_SESSION_REQUEST) &
              payloadByteMask);
    static constexpr uint8_t sessPayloadTypeRAKP1 =
        1 << (static_cast<uint8_t>(PayloadType::RAKP1) & payloadByteMask);
    static constexpr uint8_t sessPayloadTypeRAKP3 =
        1 << (static_cast<uint8_t>(PayloadType::RAKP3) & payloadByteMask);

    resp->stdPayloadType[0] = stdPayloadTypeIPMI | stdPayloadTypeSOL;
    // RMCP+ Open Session request, RAKP Message1 and RAKP Message3.
    resp->sessSetupPayloadType[0] =
        sessPayloadTypeOpenReq | sessPayloadTypeRAKP1 | sessPayloadTypeRAKP3;

    *data_len = sizeof(*resp);

    return IPMI_CC_OK;
}

void registerChannelFunctions() __attribute__((constructor));
void registerChannelFunctions()
{
    ipmiChannelInit();

    registerHandler(prioOpenBmcBase, netFnApp, app::cmdSetChannelAccess,
                    Privilege::Admin, ipmiSetChannelAccess);

    registerHandler(prioOpenBmcBase, netFnApp, app::cmdGetChannelAccess,
                    Privilege::User, ipmiGetChannelAccess);

    registerHandler(prioOpenBmcBase, netFnApp, app::cmdGetChannelInfoCommand,
                    Privilege::User, ipmiGetChannelInfo);

    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_CHANNEL_PAYLOAD_SUPPORT,
                           NULL, ipmiGetChannelPayloadSupport, PRIVILEGE_USER);

    return;
}

} // namespace ipmi
