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

// IPMI commands for user command NETFN:APP.
enum ipmi_netfn_user_cmds
{
    IPMI_CMD_SET_USER_ACCESS = 0x43,
    IPMI_CMD_GET_USER_ACCESS = 0x44,
    IPMI_CMD_SET_USER_NAME = 0x45,
    IPMI_CMD_GET_USER_NAME = 0x46,
    IPMI_CMD_SET_USER_PASSWORD = 0x47,
};

static constexpr uint8_t USER_ID_DISABLED_VIA_SET_PASSWORD = 0x2;

/** @brief The set user password IPMI command.
 *
 *  @param[in] netfn
 *  @param[in] cmd
 *  @param[in] request
 *  @param[in,out] response
 *  @param[out] data_len
 *  @param[in] context
 *
 *  @return IPMI_CC_OK on success, non-zero otherwise.
 */
ipmi_ret_t ipmi_app_set_user_password(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                      ipmi_request_t request,
                                      ipmi_response_t response,
                                      ipmi_data_len_t data_len,
                                      ipmi_context_t context);
