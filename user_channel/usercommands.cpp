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

#include <host-ipmid/ipmid-api.h>
#include <phosphor-ipmi-host/apphandler.h>
#include <security/pam_appl.h>
#include <commandutils.hpp>
#include <phosphor-logging/log.hpp>
#include <usercommands.hpp>
#include <regex>
#include "user_layer.hpp"

using namespace phosphor::logging;

namespace ipmi
{

void register_netfn_firmware_functions() __attribute__((constructor));

struct set_user_access_req_t
{
    uint8_t ch_num : 4;
    uint8_t ipmi_enabled : 1;
    uint8_t link_auth_enabled : 1;
    uint8_t access_callback : 1;
    uint8_t bits_update : 1;
    uint8_t user_id : 6;
    uint8_t reserved_1 : 2;
    uint8_t privilege : 4;
    uint8_t reserved_2 : 4;
    uint8_t sess_limit : 4; // optional byte 4
    uint8_t reserved_3 : 4;
} __attribute__((packed));

struct get_user_access_req_t
{
    uint8_t ch_num : 4;
    uint8_t reserved_1 : 4;
    uint8_t user_id : 6;
    uint8_t reserved_2 : 2;
} __attribute__((packed));

struct get_user_access_resp_t
{
    uint8_t max_ch_users : 6;
    uint8_t reserved_1 : 2;
    uint8_t enabled_users : 6;
    uint8_t enabled_status : 2;
    uint8_t fixed_users : 6;
    uint8_t reserved_2 : 2;
    user_priv_access_t priv_access;
} __attribute__((packed));

struct set_user_name_req_t
{
    uint8_t user_id : 6;
    uint8_t reserved_1 : 2;
    uint8_t user_name[16];
} __attribute__((packed));

struct get_user_name_req_t
{
    uint8_t user_id : 6;
    uint8_t reserved_1 : 2;
} __attribute__((packed));

struct get_user_name_resp_t
{
    uint8_t user_name[16];
} __attribute__((packed));

struct set_user_password_req_t
{
    uint8_t user_id : 6;
    uint8_t reserved_1 : 1;
    uint8_t ipmi_20 : 1;
    uint8_t operation : 2;
    uint8_t reserved_2 : 6;
    uint8_t user_password[MAX_IPMI_20_PASSWORD_SIZE];
} __attribute__((packed));

ipmi_ret_t ipmi_set_user_access(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request,
                                ipmi_response_t response,
                                ipmi_data_len_t data_len,
                                ipmi_context_t context)
{
    const set_user_access_req_t *req =
        static_cast<set_user_access_req_t *>(request);
    size_t req_length = *data_len;

    if (!(req_length == sizeof(*req) ||
          (req_length == (sizeof(*req) - sizeof(uint8_t) /* skip optional*/))))
    {
        log<level::DEBUG>("Set user access - Invalid Length");
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    if (req->reserved_1 != 0 || req->reserved_2 != 0 || req->reserved_3 != 0 ||
        req->sess_limit != 0 ||
        (!ipmi_user_is_valid_channel(req->ch_num) ||
         (!ipmi_user_is_valid_privilege(req->privilege))))
    // TODO: Need to check for session support and return invalid field in
    // request
    {
        log<level::DEBUG>("Set user access - Invalid field in request");
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    if (!ipmi_user_is_valid_user_id(req->user_id))
    {
        log<level::DEBUG>("Set user access - Parameter out of range");
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }
    // TODO: Determine the Channel number 0xE (Self Channel number ?)
    uint8_t ch_num = req->ch_num;
    user_priv_access_t priv_access = {0};
    uint8_t flags = USER_ACC_NO_UPDATE;
    if (req->bits_update)
    {
        priv_access.ipmi_enabled = req->ipmi_enabled;
        priv_access.link_auth_enabled = req->link_auth_enabled;
        priv_access.access_callback = req->access_callback;
        flags |= USER_ACC_OTHER_BITS_UPDATE;
    }
    priv_access.privilege = req->privilege;
    flags |= USER_ACC_PRIV_UPDATE;
    ipmi_user_set_privilege_access(req->user_id, ch_num, priv_access, flags);

    return 0;
}

ipmi_ret_t ipmi_get_user_access(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request,
                                ipmi_response_t response,
                                ipmi_data_len_t data_len,
                                ipmi_context_t context)
{
    const get_user_access_req_t *req =
        static_cast<get_user_access_req_t *>(request);
    size_t req_length = *data_len;

    *data_len = 0;

    if (req_length != sizeof(*req))
    {
        log<level::DEBUG>("Get user access - Invalid Length");
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    if (req->reserved_1 != 0 || req->reserved_2 != 0 ||
        (!ipmi_user_is_valid_channel(req->ch_num)))
    // TODO: Need to check for session support and return invalid field in
    // request
    {
        log<level::DEBUG>("Get user access - Invalid field in request");
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    if (!ipmi_user_is_valid_user_id(req->user_id))
    {
        log<level::DEBUG>("Get user access - Parameter out of range");
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    // TODO: Determine the Channel number 0xE (Self Channel number ?)
    uint8_t ch_num = req->ch_num;
    get_user_access_resp_t *resp =
        static_cast<get_user_access_resp_t *>(response);

    std::fill((uint8_t *)resp, (uint8_t *)resp + sizeof(*resp), 0);

    uint8_t max_ch_users = 0, enabled_users = 0, fixed_users = 0;
    ipmi_user_get_max_counts(max_ch_users, enabled_users, fixed_users);
    resp->max_ch_users = max_ch_users;
    resp->enabled_users = enabled_users;
    resp->fixed_users = fixed_users;
    bool enabled_state = false;
    ipmi_user_check_enabled(req->user_id, enabled_state);
    resp->enabled_status = (enabled_state == true)
                               ? USER_ID_ENABLED_VIA_SET_PASSWORD
                               : USER_ID_DISABLED_VIA_SET_PASSWORD;
    ipmi_user_get_privilege_access(req->user_id, ch_num, resp->priv_access);
    *data_len = sizeof(*resp);

    return IPMI_CC_OK;
}

ipmi_ret_t ipmi_set_user_name(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    const set_user_name_req_t *req =
        static_cast<set_user_name_req_t *>(request);
    size_t req_length = *data_len;
    *data_len = 0;

    if (req_length != sizeof(*req))
    {
        log<level::DEBUG>("Set user name - Invalid Length");
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    if (req->reserved_1)
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    if (!ipmi_user_is_valid_user_id(req->user_id))
    {
        log<level::DEBUG>("Set user name - Invalid user id");
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    return ipmi_user_set_user_name(req->user_id, (char *)req->user_name);
}

/** @brief implementes the get user name command
 *  @param[in] netfn - specifies netfn.
 *  @param[in] cmd   - specifies cmd number.
 *  @param[in] request - pointer to request data.
 *  @param[in, out] data_len - specifies request data length, and returns
 * response data length.
 *  @param[in] context - ipmi context.
 *  @returns ipmi completion code.
 */
ipmi_ret_t ipmi_get_user_name(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    const get_user_name_req_t *req =
        static_cast<get_user_name_req_t *>(request);
    size_t req_length = *data_len;

    *data_len = 0;

    if (req_length != sizeof(*req))
    {
        log<level::DEBUG>("Get user name - Invalid Length");
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    std::string user_name;
    if (ipmi_user_get_user_name(req->user_id, user_name) != IPMI_CC_OK)
    { // Invalid User ID
        log<level::DEBUG>("User Name not found",
                          entry("USER-ID:%d", (uint8_t)req->user_id));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }
    get_user_name_resp_t *resp = static_cast<get_user_name_resp_t *>(response);
    std::fill((uint8_t *)resp, (uint8_t *)resp + sizeof(*resp), 0);
    user_name.copy((char *)resp->user_name, sizeof(resp->user_name), 0);
    *data_len = sizeof(*resp);

    return IPMI_CC_OK;
}

int pam_function_conversation(int num_msg, const struct pam_message **msg,
                              struct pam_response **resp, void *appdata_ptr)
{
    if (appdata_ptr == nullptr)
    {
        return PAM_AUTH_ERR;
    }
    char *pass = reinterpret_cast<char *>(
        malloc(std::strlen(reinterpret_cast<char *>(appdata_ptr)) + 1));
    std::strcpy(pass, reinterpret_cast<char *>(appdata_ptr));

    *resp = reinterpret_cast<pam_response *>(
        calloc(num_msg, sizeof(struct pam_response)));

    for (int i = 0; i < num_msg; ++i)
    {
        if (msg[i]->msg_style != PAM_PROMPT_ECHO_OFF)
        {
            continue;
        }
        resp[i]->resp = pass;
    }
    return PAM_SUCCESS;
}

bool pam_update_passwd(const char *username, const char *password)
{
    const struct pam_conv local_conversation = {pam_function_conversation,
                                                const_cast<char *>(password)};
    pam_handle_t *local_auth_handle = NULL; // this gets set by pam_start

    if (pam_start("passwd", username, &local_conversation,
                  &local_auth_handle) != PAM_SUCCESS)
    {
        return false;
    }
    int retval = pam_chauthtok(local_auth_handle, PAM_SILENT);

    if (retval != PAM_SUCCESS)
    {
        if (retval == PAM_AUTHTOK_ERR)
        {
            log<level::DEBUG>("Authentication Failure");
        }
        else
        {
            log<level::DEBUG>("pam_chauthtok returned failure",
                              entry("ERROR=%d", retval));
        }
        pam_end(local_auth_handle, retval);
        return false;
    }
    if (pam_end(local_auth_handle, PAM_SUCCESS) != PAM_SUCCESS)
    {
        return false;
    }
    return true;
}

/** @brief implementes the set user password command
 *  @param[in] netfn - specifies netfn.
 *  @param[in] cmd   - specifies cmd number.
 *  @param[in] request - pointer to request data.
 *  @param[in, out] data_len - specifies request data length, and returns
 * response data length.
 *  @param[in] context - ipmi context.
 *  @returns ipmi completion code.
 */
ipmi_ret_t ipmi_set_user_password(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                  ipmi_request_t request,
                                  ipmi_response_t response,
                                  ipmi_data_len_t data_len,
                                  ipmi_context_t context)
{
    const set_user_password_req_t *req =
        static_cast<set_user_password_req_t *>(request);
    size_t req_length = *data_len;
    // subtract 2 bytes header to know the password length - including NULL
    uint8_t password_length = *data_len - 2;
    *data_len = 0;

    // verify input length based on operation. Required password size is 20
    // bytes as  we support only IPMI 2.0, but in order to be compatible with
    // tools, accept 16 bytes of password size too.
    if (req_length < 2 ||
        // If enable / disable user, req_length has to be >=2 & <= 22
        ((req->operation == DISABLE_USER || req->operation == ENABLE_USER) &&
         ((req_length < 2) || (req_length > sizeof(set_user_password_req_t)))))
    {
        log<level::DEBUG>("Invalid Length");
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    // If set / test password then password length has to be 16 or 20 bytes
    if (((req->operation == SET_PASSWORD) ||
         (req->operation == TEST_PASSWORD)) &&
        ((password_length != MAX_IPMI_20_PASSWORD_SIZE) &&
         (password_length != MAX_IPMI_15_PASSWORD_SIZE)))
    {
        log<level::DEBUG>("Invalid Length");
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    std::string user_name;
    if (ipmi_user_get_user_name(req->user_id, user_name) != IPMI_CC_OK)
    {
        log<level::DEBUG>("User Name not found",
                          entry("USER-ID:%d", (uint8_t)req->user_id));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }
    if (req->operation == SET_PASSWORD)
    {
        std::string passwd;
        passwd.assign((char *)req->user_password, 0, MAX_IPMI_20_PASSWORD_SIZE);
        if (!std::regex_match(passwd.c_str(),
                              std::regex("[a-zA-z_][a-zA-Z_0-9,?:`!\"]*")))
        {
            log<level::DEBUG>("Invalid password fields",
                              entry("USER-ID:%d", (uint8_t)req->user_id));
            return IPMI_CC_INVALID_FIELD_REQUEST;
        }
        if (!pam_update_passwd(user_name.c_str(), passwd.c_str()))
        {
            log<level::DEBUG>("Failed to update password",
                              entry("USER-ID:%d", (uint8_t)req->user_id));
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
    }
    else
    {
        // TODO: test the password by reading the encrypted file
        log<level::ERR>(
            "Other operations not implemented - TODO yet to implement");
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    return IPMI_CC_OK;
}

void register_netfn_firmware_functions()
{
    print_registration(NETFUN_APP, IPMI_CMD_SET_USER_ACCESS);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_SET_USER_ACCESS, NULL,
                           ipmi_set_user_access, PRIVILEGE_ADMIN);

    print_registration(NETFUN_APP, IPMI_CMD_GET_USER_ACCESS);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_USER_ACCESS, NULL,
                           ipmi_get_user_access, PRIVILEGE_ADMIN);

    print_registration(NETFUN_APP, IPMI_CMD_GET_USER_NAME);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_USER_NAME, NULL,
                           ipmi_get_user_name, PRIVILEGE_ADMIN);

    print_registration(NETFUN_APP, IPMI_CMD_SET_USER_NAME);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_SET_USER_NAME, NULL,
                           ipmi_set_user_name, PRIVILEGE_ADMIN);

    print_registration(NETFUN_APP, IPMI_CMD_SET_USER_PASSWORD);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_SET_USER_PASSWORD, NULL,
                           ipmi_set_user_password, PRIVILEGE_ADMIN);

    return;
}
} // namespace ipmi
