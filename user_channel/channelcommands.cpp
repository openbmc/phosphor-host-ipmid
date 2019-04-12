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

/** @struct SetChannelAccessReq
 *
 *  Structure for set channel access request command (refer spec sec 22.22)
 */
struct SetChannelAccessReq
{
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t chNum : 4;
    uint8_t reserved_1 : 4;
    uint8_t accessMode : 3;
    uint8_t usrAuthDisabled : 1;
    uint8_t msgAuthDisabled : 1;
    uint8_t alertDisabled : 1;
    uint8_t accessSetMode : 2;
    uint8_t privLimit : 4;
    uint8_t reserved_2 : 2;
    uint8_t privSetMode : 2;
#endif
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t reserved_1 : 4;
    uint8_t chNum : 4;
    uint8_t accessSetMode : 2;
    uint8_t alertDisabled : 1;
    uint8_t msgAuthDisabled : 1;
    uint8_t usrAuthDisabled : 1;
    uint8_t accessMode : 3;
    uint8_t privSetMode : 2;
    uint8_t reserved_2 : 2;
    uint8_t privLimit : 4;
#endif

} __attribute__((packed));

/** @struct GetChannelAccessReq
 *
 *  Structure for get channel access request command (refer spec sec 22.23)
 */
struct GetChannelAccessReq
{
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t chNum : 4;
    uint8_t reserved_1 : 4;
    uint8_t reserved_2 : 6;
    uint8_t accessSetMode : 2;
#endif
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t reserved_1 : 4;
    uint8_t chNum : 4;
    uint8_t accessSetMode : 2;
    uint8_t reserved_2 : 6;
#endif
} __attribute__((packed));

/** @struct GetChannelAccessResp
 *
 *  Structure for get channel access response command (refer spec sec 22.23)
 */
struct GetChannelAccessResp
{
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t accessMode : 3;
    uint8_t usrAuthDisabled : 1;
    uint8_t msgAuthDisabled : 1;
    uint8_t alertDisabled : 1;
    uint8_t reserved_1 : 2;
    uint8_t privLimit : 4;
    uint8_t reserved_2 : 4;
#endif
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t reserved_1 : 2;
    uint8_t alertDisabled : 1;
    uint8_t msgAuthDisabled : 1;
    uint8_t usrAuthDisabled : 1;
    uint8_t accessMode : 3;
    uint8_t reserved_2 : 4;
    uint8_t privLimit : 4;
#endif
} __attribute__((packed));

/** @struct GetChannelInfoReq
 *
 *  Structure for get channel info request command (refer spec sec 22.24)
 */
struct GetChannelInfoReq
{
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t chNum : 4;
    uint8_t reserved_1 : 4;
#endif
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t reserved_1 : 4;
    uint8_t chNum : 4;
#endif
} __attribute__((packed));

/** @struct GetChannelInfoResp
 *
 *  Structure for get channel info response command (refer spec sec 22.24)
 */
struct GetChannelInfoResp
{
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t chNum : 4;
    uint8_t reserved_1 : 4;
    uint8_t mediumType : 7;
    uint8_t reserved_2 : 1;
    uint8_t msgProtType : 5;
    uint8_t reserved_3 : 3;
    uint8_t actSessCount : 6;
    uint8_t sessType : 2;
#endif
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t reserved_1 : 4;
    uint8_t chNum : 4;
    uint8_t reserved_2 : 1;
    uint8_t mediumType : 7;
    uint8_t reserved_3 : 3;
    uint8_t msgProtType : 5;
    uint8_t sessType : 2;
    uint8_t actSessCount : 6;
#endif
    uint8_t vendorId[3];
    uint8_t auxChInfo[2];
} __attribute__((packed));

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

ipmi_ret_t ipmiSetChannelAccess(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request,
                                ipmi_response_t response,
                                ipmi_data_len_t data_len,
                                ipmi_context_t context)
{
    const SetChannelAccessReq* req = static_cast<SetChannelAccessReq*>(request);
    size_t reqLength = *data_len;

    *data_len = 0;

    if (reqLength != sizeof(*req))
    {
        log<level::DEBUG>("Set channel access - Invalid Length");
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    uint8_t chNum = convertCurrentChannelNum(req->chNum);
    if (!isValidChannel(chNum) || req->reserved_1 != 0 || req->reserved_2 != 0)
    {
        log<level::DEBUG>("Set channel access - Invalid field in request");
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    if (EChannelSessSupported::none == getChannelSessionSupport(chNum))
    {
        log<level::DEBUG>("Set channel access - No support on channel");
        return IPMI_CC_ACTION_NOT_SUPPORTED_FOR_CHANNEL;
    }

    ChannelAccess chActData;
    ChannelAccess chNVData;
    uint8_t setActFlag = 0;
    uint8_t setNVFlag = 0;
    ipmi_ret_t compCode = IPMI_CC_OK;

    switch (req->accessSetMode)
    {
        case doNotSet:
            // Do nothing
            break;
        case nvData:
            chNVData.accessMode = req->accessMode;
            chNVData.userAuthDisabled = req->usrAuthDisabled;
            chNVData.perMsgAuthDisabled = req->msgAuthDisabled;
            chNVData.alertingDisabled = req->alertDisabled;
            setNVFlag |= (setAccessMode | setUserAuthEnabled |
                          setMsgAuthEnabled | setAlertingEnabled);
            break;
        case activeData:
            chActData.accessMode = req->accessMode;
            chActData.userAuthDisabled = req->usrAuthDisabled;
            chActData.perMsgAuthDisabled = req->msgAuthDisabled;
            chActData.alertingDisabled = req->alertDisabled;
            setActFlag |= (setAccessMode | setUserAuthEnabled |
                           setMsgAuthEnabled | setAlertingEnabled);
            break;
        case reserved:
        default:
            log<level::DEBUG>("Set channel access - Invalid access set mode");
            return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    switch (req->privSetMode)
    {
        case doNotSet:
            // Do nothing
            break;
        case nvData:
            chNVData.privLimit = req->privLimit;
            setNVFlag |= setPrivLimit;
            break;
        case activeData:
            chActData.privLimit = req->privLimit;
            setActFlag |= setPrivLimit;
            break;
        case reserved:
        default:
            log<level::DEBUG>("Set channel access - Invalid access priv mode");
            return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    if (setNVFlag != 0)
    {
        compCode = setChannelAccessPersistData(chNum, chNVData, setNVFlag);
        if (compCode != IPMI_CC_OK)
        {
            log<level::DEBUG>("Set channel access - Failed to set access data");
            return compCode;
        }
    }

    if (setActFlag != 0)
    {
        compCode = setChannelAccessData(chNum, chActData, setActFlag);
        if (compCode != IPMI_CC_OK)
        {
            log<level::DEBUG>("Set channel access - Failed to set access data");
            return compCode;
        }
    }

    return IPMI_CC_OK;
}

ipmi_ret_t ipmiGetChannelAccess(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request,
                                ipmi_response_t response,
                                ipmi_data_len_t data_len,
                                ipmi_context_t context)
{
    const GetChannelAccessReq* req = static_cast<GetChannelAccessReq*>(request);
    size_t reqLength = *data_len;

    *data_len = 0;

    if (reqLength != sizeof(*req))
    {
        log<level::DEBUG>("Get channel access - Invalid Length");
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    uint8_t chNum = convertCurrentChannelNum(req->chNum);
    if (!isValidChannel(chNum) || req->reserved_1 != 0 || req->reserved_2 != 0)
    {
        log<level::DEBUG>("Get channel access - Invalid field in request");
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    if ((req->accessSetMode == doNotSet) || (req->accessSetMode == reserved))
    {
        log<level::DEBUG>("Get channel access - Invalid Access mode");
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    if (EChannelSessSupported::none == getChannelSessionSupport(chNum))
    {
        log<level::DEBUG>("Get channel access - No support on channel");
        return IPMI_CC_ACTION_NOT_SUPPORTED_FOR_CHANNEL;
    }

    GetChannelAccessResp* resp = static_cast<GetChannelAccessResp*>(response);

    std::fill(reinterpret_cast<uint8_t*>(resp),
              reinterpret_cast<uint8_t*>(resp) + sizeof(*resp), 0);

    ChannelAccess chAccess;
    ipmi_ret_t compCode = IPMI_CC_OK;

    if (req->accessSetMode == nvData)
    {
        compCode = getChannelAccessPersistData(chNum, chAccess);
    }
    else if (req->accessSetMode == activeData)
    {
        compCode = getChannelAccessData(chNum, chAccess);
    }

    if (compCode != IPMI_CC_OK)
    {
        return compCode;
    }

    resp->accessMode = chAccess.accessMode;
    resp->usrAuthDisabled = chAccess.userAuthDisabled;
    resp->msgAuthDisabled = chAccess.perMsgAuthDisabled;
    resp->alertDisabled = chAccess.alertingDisabled;
    resp->privLimit = chAccess.privLimit;

    *data_len = sizeof(*resp);
    return IPMI_CC_OK;
}

ipmi_ret_t ipmiGetChannelInfo(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    const GetChannelInfoReq* req = static_cast<GetChannelInfoReq*>(request);
    size_t reqLength = *data_len;

    *data_len = 0;

    if (reqLength != sizeof(*req))
    {
        log<level::DEBUG>("Get channel info - Invalid Length");
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    uint8_t chNum = convertCurrentChannelNum(req->chNum);
    if (!isValidChannel(chNum) || req->reserved_1 != 0)
    {
        log<level::DEBUG>("Get channel info - Invalid field in request");
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    // Check the existance of device for session-less channels.
    if ((EChannelSessSupported::none != getChannelSessionSupport(chNum)) &&
        (!(doesDeviceExist(chNum))))
    {
        log<level::DEBUG>("Get channel info - Device not exist");
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    GetChannelInfoResp* resp = static_cast<GetChannelInfoResp*>(response);

    std::fill(reinterpret_cast<uint8_t*>(resp),
              reinterpret_cast<uint8_t*>(resp) + sizeof(*resp), 0);

    ChannelInfo chInfo;
    ipmi_ret_t compCode = getChannelInfo(chNum, chInfo);
    if (compCode != IPMI_CC_OK)
    {
        return compCode;
    }

    resp->chNum = chNum;
    resp->mediumType = chInfo.mediumType;
    resp->msgProtType = chInfo.protocolType;
    resp->actSessCount = getChannelActiveSessions(chNum);
    resp->sessType = chInfo.sessionSupported;

    // IPMI Spec: The IPMI Enterprise Number is: 7154 (decimal)
    resp->vendorId[0] = 0xF2;
    resp->vendorId[1] = 0x1B;
    resp->vendorId[2] = 0x00;

    // Auxiliary Channel info  - byte 1:2
    // TODO: For System Interface(0xF) and OEM channel types, this needs
    // to be changed acoordingly.
    // All other channel types, its reverved
    resp->auxChInfo[0] = 0x00;
    resp->auxChInfo[1] = 0x00;

    *data_len = sizeof(*resp);

    return IPMI_CC_OK;
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

/** @brief implements the get channel payload version command
 *  @param ctx - IPMI context pointer (for channel)
 *  @param chNum - channel number to get info about
 *  @param reserved - skip 4 bits
 *  @param payloadTypeNo - to get payload type info

 *  @returns IPMI completion code plus response data
 *   - formatVersion - BCD encoded format version info
 */

ipmi::RspType<uint8_t> // formatVersion

    ipmiGetChannelPayloadVersionCommand(ipmi::Context::ptr ctx, uint4_t chNum,
                                        uint4_t reserved, uint8_t payloadTypeNo)
{
    uint8_t channel =
        convertCurrentChannelNum(static_cast<uint8_t>(chNum), ctx);

    if (reserved || !isValidChannel(channel) ||
        (EChannelSessSupported::none == getChannelSessionSupport(channel)))
    {
        return ipmi::responseInvalidFieldRequest();
    }

    if (!isValidPayloadType(static_cast<PayloadType>(payloadTypeNo)))
    {
        log<level::ERR>("Channel payload version - Payload type unavailable");

        constexpr uint8_t systemInfoParameterNotSupported = 0x80;
        return ipmi::response(systemInfoParameterNotSupported);
    }

    // BCD encoded version representation - 1.0
    static constexpr uint8_t formatVersion = 0x10;

    return ipmi::responseSuccess(formatVersion);
}

void registerChannelFunctions() __attribute__((constructor));
void registerChannelFunctions()
{
    ipmiChannelInit();

    ipmi_register_callback(NETFUN_APP, IPMI_CMD_SET_CHANNEL_ACCESS, NULL,
                           ipmiSetChannelAccess, PRIVILEGE_ADMIN);

    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_CHANNEL_ACCESS, NULL,
                           ipmiGetChannelAccess, PRIVILEGE_USER);

    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_CHANNEL_INFO, NULL,
                           ipmiGetChannelInfo, PRIVILEGE_USER);

    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_CHANNEL_PAYLOAD_SUPPORT,
                           NULL, ipmiGetChannelPayloadSupport, PRIVILEGE_USER);

    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdGetChannelPayloadVersion,
                          ipmi::Privilege::User,
                          ipmiGetChannelPayloadVersionCommand);
    return;
}

} // namespace ipmi
