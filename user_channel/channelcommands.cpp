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

#include "channel_layer.hpp"

#include <phosphor-logging/log.hpp>
#include <regex>

#include "apphandler.h"

using namespace phosphor::logging;

namespace ipmi
{

struct set_channel_access_req_t
{
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t ch_num : 4;
    uint8_t reserved_1 : 4;
    uint8_t access_mode : 3;
    uint8_t usr_auth_disabled : 1;
    uint8_t msg_auth_disabled : 1;
    uint8_t alert_disabled : 1;
    uint8_t access_set_mode : 2;
    uint8_t priv_limit : 4;
    uint8_t reserved_2 : 2;
    uint8_t priv_set_mode : 2;
#endif
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t reserved_1 : 4;
    uint8_t ch_num : 4;
    uint8_t access_set_mode : 2;
    uint8_t alert_disabled : 1;
    uint8_t msg_auth_disabled : 1;
    uint8_t usr_auth_disabled : 1;
    uint8_t access_mode : 3;
    uint8_t priv_set_mode : 2;
    uint8_t reserved_2 : 2;
    uint8_t priv_limit : 4;
#endif

} __attribute__((packed));

struct get_channel_access_req_t
{
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t ch_num : 4;
    uint8_t reserved_1 : 4;
    uint8_t reserved_2 : 6;
    uint8_t access_set_mode : 2;
#endif
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t reserved_1 : 4;
    uint8_t ch_num : 4;
    uint8_t access_set_mode : 2;
    uint8_t reserved_2 : 6;
#endif
} __attribute__((packed));

struct get_channel_access_resp_t
{
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t access_mode : 3;
    uint8_t usr_auth_disabled : 1;
    uint8_t msg_auth_disabled : 1;
    uint8_t alert_disabled : 1;
    uint8_t reserved_1 : 2;
    uint8_t priv_limit : 4;
    uint8_t reserved_2 : 4;
#endif
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t reserved_1 : 2;
    uint8_t alert_disabled : 1;
    uint8_t msg_auth_disabled : 1;
    uint8_t usr_auth_disabled : 1;
    uint8_t access_mode : 3;
    uint8_t reserved_2 : 4;
    uint8_t priv_limit : 4;
#endif
} __attribute__((packed));

struct get_channel_info_req_t
{
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t ch_num : 4;
    uint8_t reserved_1 : 4;
#endif
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t reserved_1 : 4;
    uint8_t ch_num : 4;
#endif
} __attribute__((packed));

struct get_channel_info_resp_t
{
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t ch_num : 4;
    uint8_t reserved_1 : 4;
    uint8_t medium_type : 7;
    uint8_t reserved_2 : 1;
    uint8_t msg_prot_type : 5;
    uint8_t reserved_3 : 3;
    uint8_t act_sess_count : 6;
    uint8_t sess_type : 2;
#endif
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t reserved_1 : 4;
    uint8_t ch_num : 4;
    uint8_t reserved_2 : 1;
    uint8_t medium_type : 7;
    uint8_t reserved_3 : 3;
    uint8_t msg_prot_type : 5;
    uint8_t sess_type : 2;
    uint8_t act_sess_count : 6;
#endif
    uint8_t vendor_id[3];
    uint8_t aux_ch_info[2];
} __attribute__((packed));

ipmi_ret_t ipmi_set_channel_access(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                   ipmi_request_t request,
                                   ipmi_response_t response,
                                   ipmi_data_len_t data_len,
                                   ipmi_context_t context)
{
    const set_channel_access_req_t* req =
        static_cast<set_channel_access_req_t*>(request);
    size_t req_length = *data_len;

    *data_len = 0;

    if (req_length != sizeof(*req))
    {
        log<level::DEBUG>("Set channel access - Invalid Length");
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    // TODO: Self channel number (0xE) has to be determined.
    uint8_t chNum = req->ch_num;
    if (!isValidChannel(chNum))
    {
        log<level::DEBUG>("Set channel access - Parameter out of range");
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    if (sessionNone == getChannelSessionSupport(chNum))
    {
        log<level::DEBUG>("Set channel access - No support on channel");
        return IPMI_CC_ACTION_NOT_SUPPORTED_FOR_CHANNEL;
    }

    ChannelAccess chActData;
    ChannelAccess chNVData;
    uint8_t setActFlag = 0;
    uint8_t setNVFlag = 0;
    ipmi_ret_t compCode = IPMI_CC_OK;

    switch (req->access_set_mode)
    {
        case doNotSet:
            // Do nothing
            break;
        case nvData:
            chNVData.accessMode = req->access_mode;
            chNVData.userAuthDisabled = req->usr_auth_disabled;
            chNVData.perMsgAuthDisabled = req->msg_auth_disabled;
            chNVData.alertingDisabled = req->alert_disabled;
            setNVFlag |= (setAccessMode | setUserAuthEnabled |
                          setMsgAuthEnabled | setAlertingEnabled);
            break;
        case activeData:
            chActData.accessMode = req->access_mode;
            chActData.userAuthDisabled = req->usr_auth_disabled;
            chActData.perMsgAuthDisabled = req->msg_auth_disabled;
            chActData.alertingDisabled = req->alert_disabled;
            setActFlag |= (setAccessMode | setUserAuthEnabled |
                           setMsgAuthEnabled | setAlertingEnabled);
            break;
        case reserved:
        default:
            log<level::DEBUG>("Set channel access - Invalid access set mode");
            return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    switch (req->priv_set_mode)
    {
        case doNotSet:
            // Do nothing
            break;
        case nvData:
            chNVData.privLimit = req->priv_limit;
            setNVFlag |= setPrivLimit;
            break;
        case activeData:
            chActData.privLimit = req->priv_limit;
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

ipmi_ret_t ipmi_get_channel_access(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                   ipmi_request_t request,
                                   ipmi_response_t response,
                                   ipmi_data_len_t data_len,
                                   ipmi_context_t context)
{
    const get_channel_access_req_t* req =
        static_cast<get_channel_access_req_t*>(request);
    size_t req_length = *data_len;

    *data_len = 0;

    if (req_length != sizeof(*req))
    {
        log<level::DEBUG>("Get channel access - Invalid Length");
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    // TODO: Self channel number (0xE) has to be determined.
    uint8_t chNum = req->ch_num;
    if (!isValidChannel(chNum))
    {
        log<level::DEBUG>("Get channel access - Parameter out of range");
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    if ((req->access_set_mode == doNotSet) ||
        (req->access_set_mode == reserved))
    {
        log<level::DEBUG>("Get channel access - Invalid Access mode");
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    if (sessionNone == getChannelSessionSupport(chNum))
    {
        log<level::DEBUG>("Get channel access - No support on channel");
        return IPMI_CC_ACTION_NOT_SUPPORTED_FOR_CHANNEL;
    }

    get_channel_access_resp_t* resp =
        static_cast<get_channel_access_resp_t*>(response);

    std::fill(reinterpret_cast<uint8_t*>(resp),
              reinterpret_cast<uint8_t*>(resp) + sizeof(*resp), 0);

    ChannelAccess chAccess;
    ipmi_ret_t compCode = IPMI_CC_OK;

    if (req->access_set_mode == nvData)
    {
        compCode = getChannelAccessPersistData(chNum, chAccess);
    }
    else if (req->access_set_mode == activeData)
    {
        compCode = getChannelAccessData(chNum, chAccess);
    }

    if (compCode != IPMI_CC_OK)
    {
        return compCode;
    }

    resp->access_mode = chAccess.accessMode;
    resp->usr_auth_disabled = chAccess.userAuthDisabled;
    resp->msg_auth_disabled = chAccess.perMsgAuthDisabled;
    resp->alert_disabled = chAccess.alertingDisabled;
    resp->priv_limit = chAccess.privLimit;

    *data_len = sizeof(*resp);
    return IPMI_CC_OK;
}

ipmi_ret_t ipmi_get_channel_info(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                 ipmi_request_t request,
                                 ipmi_response_t response,
                                 ipmi_data_len_t data_len,
                                 ipmi_context_t context)
{
    const get_channel_info_req_t* req =
        static_cast<get_channel_info_req_t*>(request);
    size_t req_length = *data_len;

    *data_len = 0;

    if (req_length != sizeof(*req))
    {
        log<level::DEBUG>("Get channel info - Invalid Length");
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    // TODO: Self channel number (0xE) has to be determined.
    uint8_t chNum = req->ch_num;
    if (!isValidChannel(chNum))
    {
        log<level::DEBUG>("Get channel info - Parameter out of range");
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    // Check the existance of device for session-less channels.
    if ((sessionNone != getChannelSessionSupport(chNum)) &&
        (!(doesDeviceExist(chNum))))
    {
        log<level::DEBUG>("Get channel info - Device not exist");
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    get_channel_info_resp_t* resp =
        static_cast<get_channel_info_resp_t*>(response);

    std::fill(reinterpret_cast<uint8_t*>(resp),
              reinterpret_cast<uint8_t*>(resp) + sizeof(*resp), 0);

    ChannelInfo chInfo;
    ipmi_ret_t compCode = getChannelInfo(chNum, chInfo);
    if (compCode != IPMI_CC_OK)
    {
        return compCode;
    }

    resp->ch_num = chNum;
    resp->medium_type = chInfo.mediumType;
    resp->msg_prot_type = chInfo.protocolType;
    resp->act_sess_count = getChannelActiveSessions(chNum);
    resp->sess_type = chInfo.sessionSupported;

    // IPMI Spec: The IPMI Enterprise Number is: 7154 (decimal)
    resp->vendor_id[0] = 0xF2;
    resp->vendor_id[1] = 0x1B;
    resp->vendor_id[2] = 0x00;

    // Auxiliary Channel info  - byte 1:2
    // TODO: For System Interface(0xF) and OEM channel types, this needs
    // to be changed acoordingly.
    // All other channel types, its reverved
    resp->aux_ch_info[0] = 0x00;
    resp->aux_ch_info[1] = 0x00;

    *data_len = sizeof(*resp);

    return IPMI_CC_OK;
}

void registerChannelFunctions()
{
    ipmiChannelInit();

    ipmi_register_callback(NETFUN_APP, IPMI_CMD_SET_CHANNEL_ACCESS, NULL,
                           ipmi_set_channel_access, PRIVILEGE_ADMIN);

    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_CHANNEL_ACCESS, NULL,
                           ipmi_get_channel_access, PRIVILEGE_ADMIN);

    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_CHANNEL_INFO, NULL,
                           ipmi_get_channel_info, PRIVILEGE_ADMIN);
    return;
}

} // namespace ipmi
