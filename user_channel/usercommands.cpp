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

#include "usercommands.hpp"

#include "apphandler.hpp"
#include "channel_layer.hpp"
#include "user_layer.hpp"

#include <ipmid/api.h>
#include <security/pam_appl.h>

#include <ipmid/api.hpp>
#include <ipmid/registration.hpp>
#include <phosphor-logging/log.hpp>
#include <regex>

namespace ipmi
{

using namespace phosphor::logging;

static constexpr uint8_t disableUser = 0x00;
static constexpr uint8_t enableUser = 0x01;
static constexpr uint8_t setPassword = 0x02;
static constexpr uint8_t testPassword = 0x03;
static constexpr uint8_t passwordKeySize20 = 1;
static constexpr uint8_t passwordKeySize16 = 0;

/** @struct SetUserAccessReq
 *
 *  Structure for set user access request command (refer spec sec 22.26)
 */
struct SetUserAccessReq
{
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t chNum : 4;
    uint8_t ipmiEnabled : 1;
    uint8_t linkAuthEnabled : 1;
    uint8_t accessCallback : 1;
    uint8_t bitsUpdate : 1;
    uint8_t userId : 6;
    uint8_t reserved1 : 2;
    uint8_t privilege : 4;
    uint8_t reserved2 : 4;
    uint8_t sessLimit : 4; // optional byte 4
    uint8_t reserved3 : 4;
#endif
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t bitsUpdate : 1;
    uint8_t accessCallback : 1;
    uint8_t linkAuthEnabled : 1;
    uint8_t ipmiEnabled : 1;
    uint8_t chNum : 4;
    uint8_t reserved1 : 2;
    uint8_t userId : 6;
    uint8_t reserved2 : 4;
    uint8_t privilege : 4;
    uint8_t reserved3 : 4;
    uint8_t sessLimit : 4; // optional byte 4
#endif

} __attribute__((packed));

/** @struct GetUserAccessReq
 *
 *  Structure for get user access request command (refer spec sec 22.27)
 */
struct GetUserAccessReq
{
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t chNum : 4;
    uint8_t reserved1 : 4;
    uint8_t userId : 6;
    uint8_t reserved2 : 2;
#endif
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t reserved1 : 4;
    uint8_t chNum : 4;
    uint8_t reserved2 : 2;
    uint8_t userId : 6;
#endif
} __attribute__((packed));

/** @struct GetUserAccessResp
 *
 *  Structure for get user access response command (refer spec sec 22.27)
 */
struct GetUserAccessResp
{
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t maxChUsers : 6;
    uint8_t reserved1 : 2;
    uint8_t enabledUsers : 6;
    uint8_t enabledStatus : 2;
    uint8_t fixedUsers : 6;
    uint8_t reserved2 : 2;
#endif
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t reserved1 : 2;
    uint8_t maxChUsers : 6;
    uint8_t enabledStatus : 2;
    uint8_t enabledUsers : 6;
    uint8_t reserved2 : 2;
    uint8_t fixedUsers : 6;
#endif
    PrivAccess privAccess;
} __attribute__((packed));

/** @struct SetUserNameReq
 *
 *  Structure for set user name request command (refer spec sec 22.28)
 */
struct SetUserNameReq
{
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t userId : 6;
    uint8_t reserved1 : 2;
#endif
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t reserved1 : 2;
    uint8_t userId : 6;
#endif
    uint8_t userName[16];
} __attribute__((packed));

/** @struct GetUserNameReq
 *
 *  Structure for get user name request command (refer spec sec 22.29)
 */
struct GetUserNameReq
{
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t userId : 6;
    uint8_t reserved1 : 2;
#endif
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t reserved1 : 2;
    uint8_t userId : 6;
#endif
} __attribute__((packed));

/** @struct GetUserNameResp
 *
 *  Structure for get user name response command (refer spec sec 22.29)
 */
struct GetUserNameResp
{
    uint8_t userName[16];
} __attribute__((packed));

/** @struct SetUserPasswordReq
 *
 *  Structure for set user password request command (refer spec sec 22.30)
 */
struct SetUserPasswordReq
{
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t userId : 6;
    uint8_t reserved1 : 1;
    uint8_t ipmi20 : 1;
    uint8_t operation : 2;
    uint8_t reserved2 : 6;
#endif
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t ipmi20 : 1;
    uint8_t reserved1 : 1;
    uint8_t userId : 6;
    uint8_t reserved2 : 6;
    uint8_t operation : 2;
#endif
    uint8_t userPassword[maxIpmi20PasswordSize];
} __attribute__((packed));

ipmi_ret_t ipmiSetUserAccess(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t dataLen, ipmi_context_t context)
{
    const SetUserAccessReq* req = static_cast<SetUserAccessReq*>(request);
    size_t reqLength = *dataLen;
    *dataLen = 0;

    if (!(reqLength == sizeof(*req) ||
          (reqLength == (sizeof(*req) - sizeof(uint8_t) /* skip optional*/))))
    {
        log<level::DEBUG>("Set user access - Invalid Length");
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    uint8_t chNum = convertCurrentChannelNum(req->chNum);
    if (req->reserved1 != 0 || req->reserved2 != 0 || req->reserved3 != 0 ||
        req->sessLimit != 0 || (!isValidChannel(chNum)) ||
        (!ipmiUserIsValidPrivilege(req->privilege)) ||
        (EChannelSessSupported::none == getChannelSessionSupport(chNum)))
    {
        log<level::DEBUG>("Set user access - Invalid field in request");
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    if (!ipmiUserIsValidUserId(req->userId))
    {
        log<level::DEBUG>("Set user access - Parameter out of range");
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    PrivAccess privAccess = {0};
    if (req->bitsUpdate)
    {
        privAccess.ipmiEnabled = req->ipmiEnabled;
        privAccess.linkAuthEnabled = req->linkAuthEnabled;
        privAccess.accessCallback = req->accessCallback;
    }
    privAccess.privilege = req->privilege;
    return ipmiUserSetPrivilegeAccess(req->userId, chNum, privAccess,
                                      req->bitsUpdate);
}

ipmi_ret_t ipmiGetUserAccess(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t dataLen, ipmi_context_t context)
{
    const GetUserAccessReq* req = static_cast<GetUserAccessReq*>(request);
    size_t reqLength = *dataLen;
    ipmi_ret_t retStatus = IPMI_CC_OK;

    *dataLen = 0;

    if (reqLength != sizeof(*req))
    {
        log<level::DEBUG>("Get user access - Invalid Length");
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    uint8_t chNum = convertCurrentChannelNum(req->chNum);
    if (req->reserved1 != 0 || req->reserved2 != 0 ||
        (!isValidChannel(chNum)) ||
        (EChannelSessSupported::none == getChannelSessionSupport(chNum)))
    {
        log<level::DEBUG>("Get user access - Invalid field in request");
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    if (!ipmiUserIsValidUserId(req->userId))
    {
        log<level::DEBUG>("Get user access - Parameter out of range");
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    uint8_t maxChUsers = 0, enabledUsers = 0, fixedUsers = 0;
    bool enabledState = false;
    GetUserAccessResp* resp = static_cast<GetUserAccessResp*>(response);

    std::fill(reinterpret_cast<uint8_t*>(resp),
              reinterpret_cast<uint8_t*>(resp) + sizeof(*resp), 0);

    retStatus = ipmiUserGetAllCounts(maxChUsers, enabledUsers, fixedUsers);
    if (retStatus != IPMI_CC_OK)
    {
        return retStatus;
    }

    resp->maxChUsers = maxChUsers;
    resp->enabledUsers = enabledUsers;
    resp->fixedUsers = fixedUsers;

    retStatus = ipmiUserCheckEnabled(req->userId, enabledState);
    if (retStatus != IPMI_CC_OK)
    {
        return retStatus;
    }

    resp->enabledStatus = enabledState ? userIdEnabledViaSetPassword
                                       : userIdDisabledViaSetPassword;
    *dataLen = sizeof(*resp);
    return ipmiUserGetPrivilegeAccess(req->userId, chNum, resp->privAccess);
}

ipmi_ret_t ipmiSetUserName(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                           ipmi_request_t request, ipmi_response_t response,
                           ipmi_data_len_t dataLen, ipmi_context_t context)
{
    const SetUserNameReq* req = static_cast<SetUserNameReq*>(request);
    size_t reqLength = *dataLen;
    *dataLen = 0;

    if (reqLength != sizeof(*req))
    {
        log<level::DEBUG>("Set user name - Invalid Length");
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    if (req->reserved1)
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    if (!ipmiUserIsValidUserId(req->userId))
    {
        log<level::DEBUG>("Set user name - Invalid user id");
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    return ipmiUserSetUserName(req->userId,
                               reinterpret_cast<const char*>(req->userName));
}

/** @brief implementes the get user name command
 *  @param[in] netfn - specifies netfn.
 *  @param[in] cmd   - specifies cmd number.
 *  @param[in] request - pointer to request data.
 *  @param[in, out] dataLen - specifies request data length, and returns
 * response data length.
 *  @param[in] context - ipmi context.
 *  @returns ipmi completion code.
 */
ipmi_ret_t ipmiGetUserName(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                           ipmi_request_t request, ipmi_response_t response,
                           ipmi_data_len_t dataLen, ipmi_context_t context)
{
    const GetUserNameReq* req = static_cast<GetUserNameReq*>(request);
    size_t reqLength = *dataLen;

    *dataLen = 0;

    if (reqLength != sizeof(*req))
    {
        log<level::DEBUG>("Get user name - Invalid Length");
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    std::string userName;
    if (ipmiUserGetUserName(req->userId, userName) != IPMI_CC_OK)
    { // Invalid User ID
        log<level::DEBUG>("User Name not found",
                          entry("USER-ID:%d", (uint8_t)req->userId));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }
    GetUserNameResp* resp = static_cast<GetUserNameResp*>(response);
    std::fill(reinterpret_cast<uint8_t*>(resp),
              reinterpret_cast<uint8_t*>(resp) + sizeof(*resp), 0);
    userName.copy(reinterpret_cast<char*>(resp->userName),
                  sizeof(resp->userName), 0);
    *dataLen = sizeof(*resp);

    return IPMI_CC_OK;
}

/** @brief implementes the set user password command
 *  @param[in] netfn - specifies netfn.
 *  @param[in] cmd   - specifies cmd number.
 *  @param[in] request - pointer to request data.
 *  @param[in, out] dataLen - specifies request data length, and returns
 * response data length.
 *  @param[in] context - ipmi context.
 *  @returns ipmi completion code.
 */
ipmi_ret_t ipmiSetUserPassword(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                               ipmi_request_t request, ipmi_response_t response,
                               ipmi_data_len_t dataLen, ipmi_context_t context)
{
    const SetUserPasswordReq* req = static_cast<SetUserPasswordReq*>(request);
    size_t reqLength = *dataLen;
    // subtract 2 bytes header to know the password length - including NULL
    uint8_t passwordLength = *dataLen - 2;
    *dataLen = 0;

    // verify input length based on operation. Required password size is 20
    // bytes as  we support only IPMI 2.0, but in order to be compatible with
    // tools, accept 16 bytes of password size too.
    if (reqLength < 2 ||
        // If enable / disable user, reqLength has to be >=2 & <= 22
        ((req->operation == disableUser || req->operation == enableUser) &&
         ((reqLength < 2) || (reqLength > sizeof(SetUserPasswordReq)))))
    {
        log<level::DEBUG>("Invalid Length");
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    // If set / test password then password length has to be 16 or 20 bytes
    // based on the password size bit.
    if (((req->operation == setPassword) || (req->operation == testPassword)) &&
        (((req->ipmi20 == passwordKeySize20) &&
          (passwordLength != maxIpmi20PasswordSize)) ||
         ((req->ipmi20 == passwordKeySize16) &&
          (passwordLength != maxIpmi15PasswordSize))))
    {
        log<level::DEBUG>("Invalid Length");
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    std::string userName;
    if (ipmiUserGetUserName(req->userId, userName) != IPMI_CC_OK)
    {
        log<level::DEBUG>("User Name not found",
                          entry("USER-ID:%d", (uint8_t)req->userId));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }
    if (req->operation == setPassword)
    {
        return ipmiUserSetUserPassword(
            req->userId, reinterpret_cast<const char*>(req->userPassword));
    }
    else if (req->operation == enableUser || req->operation == disableUser)
    {
        return ipmiUserUpdateEnabledState(req->userId,
                                          static_cast<bool>(req->operation));
    }
    else if (req->operation == testPassword)
    {
        auto password = ipmiUserGetPassword(userName);
        std::string testPassword(
            reinterpret_cast<const char*>(req->userPassword), 0,
            passwordLength);
        // Note: For security reasons password size won't be compared and
        // wrong password size completion code will not be returned if size
        // doesn't match as specified in IPMI specification.
        if (password != testPassword)
        {
            log<level::DEBUG>("Test password failed",
                              entry("USER-ID:%d", (uint8_t)req->userId));
            return static_cast<ipmi_ret_t>(
                IPMISetPasswordReturnCodes::ipmiCCPasswdFailMismatch);
        }
        return IPMI_CC_OK;
    }
    return IPMI_CC_INVALID_FIELD_REQUEST;
}

/** @brief implements the get channel authentication command
 *  @param ctx - IPMI context pointer (for channel)
 *  @param extData - get IPMI 2.0 extended data
 *  @param reserved1 - skip 3 bits
 *  @param chNum - channel number to get info about
 *  @param reserved2 - skip 4 bits
 *  @param privLevel - requested privilege level

 *  @returns ipmi completion code plus response data
 *   - channel number
 *   - rmcpAuthTypes - RMCP auth types (IPMI 1.5)
 *   - reserved1
 *   - extDataSupport - true for IPMI 2.0 extensions
 *   - anonymousLogin - true for anonymous login enabled
 *   - nullUsers - true for null user names enabled
 *   - nonNullUsers - true for non-null usernames enabled
 *   - userAuth - false for user authentication enabled
 *   - perMessageAuth - false for per message authentication enabled
 *   - KGStatus - true for Kg required for authentication
 *   - reserved2
 *   - rmcp - RMCP (IPMI 1.5) connection support
 *   - rmcpp - RMCP+ (IPMI 2.0) connection support
 *   - reserved3
 *   - oemID - OEM IANA of any OEM auth support
 *   - oemAuxillary - OEM data for auth
 */
ipmi::
    RspType<
        // byte 1 is completion code
        // byte 2
        uint8_t,  // channel number
                  // byte 3
        uint6_t,  // rmcpAuthTypes
        bool,     // reserved1
        bool,     // extDataSupport
                  // byte 4
        bool,     // anonymousLogin
        bool,     // nullUsers
        bool,     // nonNullUsers
        bool,     // userAuth
        bool,     // perMessageAuth
        bool,     // KGStatus
        uint2_t,  // reserved2
                  // byte 5
        bool,     // rmcp
        bool,     // rmcpp
        uint6_t,  // reserved3
                  // byte 6-8
        uint24_t, // oemID
                  // byte 9
        uint8_t   // oemAuxillary
        >
    ipmiGetChannelAuthenticationCapabilities(ipmi::Context::ptr ctx,
                                             uint4_t chNum, uint3_t reserved1,
                                             bool extData, uint4_t privLevel,
                                             uint4_t reserved2)
{

    uint8_t channel =
        convertCurrentChannelNum(static_cast<uint8_t>(chNum), ctx);

    if (reserved1 || reserved2 || !isValidChannel(channel) ||
        !isValidPrivLimit(static_cast<uint8_t>(privLevel)) ||
        (EChannelSessSupported::none == getChannelSessionSupport(channel)))
    {
        return ipmi::response(ccInvalidFieldRequest);
    }

    constexpr bool extDataSupport = true; // true for IPMI 2.0 extensions
    constexpr bool reserved3 = false;
    constexpr uint6_t rmcpAuthTypes = 0; // IPMI 1.5 auth types - not supported
    constexpr uint2_t reserved4 = 0;
    constexpr bool KGStatus = false; // Not supporting now.
    constexpr bool perMessageAuth =
        false;                        // Per message authentication - enabled
    constexpr bool userAuth = false;  // User authentication - enabled
    constexpr bool nullUsers = false; // Null user names - not supported
    constexpr bool anonymousLogin = false; // Anonymous login - not supported
    constexpr uint6_t reserved5 = 0;
    constexpr bool rmcpp = true; // IPMI 2.0 - supported
    constexpr bool rmcp = false; // IPMI 1.5 - not supported
    constexpr uint24_t oemID = 0;
    constexpr uint8_t oemAuxillary = 0;

    bool nonNullUsers = 0;
    uint8_t maxChUsers = 0, enabledUsers = 0, fixedUsers = 0;
    ipmi::ipmiUserGetAllCounts(maxChUsers, enabledUsers, fixedUsers);
    nonNullUsers = enabledUsers > 0;

    return ipmi::responseSuccess(
        channel, rmcpAuthTypes, reserved3, extDataSupport, anonymousLogin,
        nullUsers, nonNullUsers, userAuth, perMessageAuth, KGStatus, reserved4,
        rmcp, rmcpp, reserved5, oemID, oemAuxillary);
}

void registerUserIpmiFunctions() __attribute__((constructor));
void registerUserIpmiFunctions()
{
    ipmiUserInit();
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_SET_USER_ACCESS, NULL,
                           ipmiSetUserAccess, PRIVILEGE_ADMIN);

    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_USER_ACCESS, NULL,
                           ipmiGetUserAccess, PRIVILEGE_OPERATOR);

    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_USER_NAME, NULL,
                           ipmiGetUserName, PRIVILEGE_OPERATOR);

    ipmi_register_callback(NETFUN_APP, IPMI_CMD_SET_USER_NAME, NULL,
                           ipmiSetUserName, PRIVILEGE_ADMIN);

    ipmi_register_callback(NETFUN_APP, IPMI_CMD_SET_USER_PASSWORD, NULL,
                           ipmiSetUserPassword, PRIVILEGE_ADMIN);

    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdGetChannelAuthCapabilities,
                          ipmi::Privilege::Callback,
                          ipmiGetChannelAuthenticationCapabilities);
    return;
}
} // namespace ipmi
