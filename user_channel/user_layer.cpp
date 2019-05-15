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

#include "user_layer.hpp"

#include "passwd_mgr.hpp"
#include "user_mgmt.hpp"

namespace
{
ipmi::PasswdMgr passwdMgr;
}

namespace ipmi
{

ipmi_ret_t ipmiUserInit()
{
    getUserAccessObject();
    return IPMI_CC_OK;
}

std::string ipmiUserGetPassword(const std::string& userName)
{
    return passwdMgr.getPasswdByUserName(userName);
}

ipmi_ret_t ipmiClearUserEntryPassword(const std::string& userName)
{
    if (passwdMgr.updateUserEntry(userName, "") != 0)
    {
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    return IPMI_CC_OK;
}

ipmi_ret_t ipmiRenameUserEntryPassword(const std::string& userName,
                                       const std::string& newUserName)
{
    if (passwdMgr.updateUserEntry(userName, newUserName) != 0)
    {
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    return IPMI_CC_OK;
}

bool ipmiUserIsValidUserId(const uint8_t userId)
{
    return UserAccess::isValidUserId(userId);
}

bool ipmiUserIsValidPrivilege(const uint8_t priv)
{
    return UserAccess::isValidPrivilege(priv);
}

uint8_t ipmiUserGetUserId(const std::string& userName)
{
    return getUserAccessObject().getUserId(userName);
}

ipmi_ret_t ipmiUserSetUserName(const uint8_t userId, const char* userName)
{
    return getUserAccessObject().setUserName(userId, userName);
}

ipmi_ret_t ipmiUserGetUserName(const uint8_t userId, std::string& userName)
{
    return getUserAccessObject().getUserName(userId, userName);
}

ipmi_ret_t ipmiUserSetUserPassword(const uint8_t userId,
                                   const char* userPassword)
{
    return getUserAccessObject().setUserPassword(userId, userPassword);
}

ipmi_ret_t ipmiSetSpecialUserPassword(const std::string& userName,
                                      const std::string& userPassword)
{
    return getUserAccessObject().setSpecialUserPassword(userName, userPassword);
}

ipmi_ret_t ipmiUserGetAllCounts(uint8_t& maxChUsers, uint8_t& enabledUsers,
                                uint8_t& fixedUsers)
{
    maxChUsers = ipmiMaxUsers;
    UsersTbl* userData = getUserAccessObject().getUsersTblPtr();
    enabledUsers = 0;
    fixedUsers = 0;
    // user index 0 is reserved, starts with 1
    for (size_t count = 1; count <= ipmiMaxUsers; ++count)
    {
        if (userData->user[count].userEnabled)
        {
            enabledUsers++;
        }
        if (userData->user[count].fixedUserName)
        {
            fixedUsers++;
        }
    }
    return IPMI_CC_OK;
}

ipmi_ret_t ipmiUserUpdateEnabledState(const uint8_t userId, const bool& state)
{
    return getUserAccessObject().setUserEnabledState(userId, state);
}

ipmi_ret_t ipmiUserCheckEnabled(const uint8_t userId, bool& state)
{
    if (!UserAccess::isValidUserId(userId))
    {
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }
    UserInfo* userInfo = getUserAccessObject().getUserInfo(userId);
    state = userInfo->userEnabled;
    return IPMI_CC_OK;
}

ipmi_ret_t ipmiUserGetPrivilegeAccess(const uint8_t userId, const uint8_t chNum,
                                      PrivAccess& privAccess)
{

    if (!UserAccess::isValidChannel(chNum))
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    if (!UserAccess::isValidUserId(userId))
    {
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }
    UserInfo* userInfo = getUserAccessObject().getUserInfo(userId);
    privAccess.privilege = userInfo->userPrivAccess[chNum].privilege;
    privAccess.ipmiEnabled = userInfo->userPrivAccess[chNum].ipmiEnabled;
    privAccess.linkAuthEnabled =
        userInfo->userPrivAccess[chNum].linkAuthEnabled;
    privAccess.accessCallback = userInfo->userPrivAccess[chNum].accessCallback;

    return IPMI_CC_OK;
}

ipmi_ret_t ipmiUserSetPrivilegeAccess(const uint8_t userId, const uint8_t chNum,
                                      const PrivAccess& privAccess,
                                      const bool& otherPrivUpdates)
{
    UserPrivAccess userPrivAccess;
    userPrivAccess.privilege = privAccess.privilege;
    if (otherPrivUpdates)
    {
        userPrivAccess.ipmiEnabled = privAccess.ipmiEnabled;
        userPrivAccess.linkAuthEnabled = privAccess.linkAuthEnabled;
        userPrivAccess.accessCallback = privAccess.accessCallback;
    }
    return getUserAccessObject().setUserPrivilegeAccess(
        userId, chNum, userPrivAccess, otherPrivUpdates);
}

ipmi_ret_t ipmiUserSetPayloadAccess(const uint8_t userId, const uint8_t chNum,
                                    const uint8_t operation,
                                    PayloadAccess& payloadAccess)
{

    if (!UserAccess::isValidChannel(chNum))
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    if (!UserAccess::isValidUserId(userId))
    {
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    return getUserAccessObject().setUserPayloadAccess(userId, chNum,
                                                      payloadAccess, operation);
}

ipmi_ret_t ipmiUserGetPayloadAccess(const uint8_t userId, const uint8_t chNum,
                                    PayloadAccess& payloadAccess)
{

    if (!UserAccess::isValidChannel(chNum))
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    if (!UserAccess::isValidUserId(userId))
    {
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    UserInfo* userInfo = getUserAccessObject().getUserInfo(userId);
    payloadAccess.stdPayload0ipmiReserved =
        userInfo->payloadAccess[chNum].stdPayload0ipmiReserved;
    payloadAccess.stdPayload1SOL =
        userInfo->payloadAccess[chNum].stdPayload1SOL;
    payloadAccess.stdPayload2 = userInfo->payloadAccess[chNum].stdPayload2;
    payloadAccess.stdPayload3 = userInfo->payloadAccess[chNum].stdPayload3;
    payloadAccess.stdPayload4 = userInfo->payloadAccess[chNum].stdPayload4;
    payloadAccess.stdPayload5 = userInfo->payloadAccess[chNum].stdPayload5;
    payloadAccess.stdPayload6 = userInfo->payloadAccess[chNum].stdPayload6;
    payloadAccess.stdPayload7 = userInfo->payloadAccess[chNum].stdPayload7;

    payloadAccess.stdPayloadEnables2Reserved =
        userInfo->payloadAccess[chNum].stdPayloadEnables2Reserved;

    payloadAccess.oemPayload0 = userInfo->payloadAccess[chNum].oemPayload0;
    payloadAccess.oemPayload1 = userInfo->payloadAccess[chNum].oemPayload1;
    payloadAccess.oemPayload2 = userInfo->payloadAccess[chNum].oemPayload2;
    payloadAccess.oemPayload3 = userInfo->payloadAccess[chNum].oemPayload3;
    payloadAccess.oemPayload4 = userInfo->payloadAccess[chNum].oemPayload4;
    payloadAccess.oemPayload5 = userInfo->payloadAccess[chNum].oemPayload5;
    payloadAccess.oemPayload6 = userInfo->payloadAccess[chNum].oemPayload6;
    payloadAccess.oemPayload7 = userInfo->payloadAccess[chNum].oemPayload7;

    payloadAccess.oemPayloadEnables2Reserved =
        userInfo->payloadAccess[chNum].oemPayloadEnables2Reserved;

    return IPMI_CC_OK;
}

} // namespace ipmi
