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
#include <ipmid/api.h>

#include <string>

namespace ipmi
{

// TODO: Has to be replaced with proper channel number assignment logic
/**
 * @enum Channel Id
 */
enum class EChannelID : uint8_t
{
    chanLan1 = 0x01
};

static constexpr uint8_t invalidUserId = 0xFF;
static constexpr uint8_t reservedUserId = 0x0;
static constexpr uint8_t ipmiMaxUserName = 16;
static constexpr uint8_t ipmiMaxUsers = 15;
static constexpr uint8_t ipmiMaxChannels = 16;
static constexpr uint8_t maxIpmi20PasswordSize = 20;
static constexpr uint8_t maxIpmi15PasswordSize = 16;

/** @struct PrivAccess
 *
 *  User privilege related access data as per IPMI specification.(refer spec
 * sec 22.26)
 */
struct PrivAccess
{
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t privilege : 4;
    uint8_t ipmiEnabled : 1;
    uint8_t linkAuthEnabled : 1;
    uint8_t accessCallback : 1;
    uint8_t reserved : 1;
#endif
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t reserved : 1;
    uint8_t accessCallback : 1;
    uint8_t linkAuthEnabled : 1;
    uint8_t ipmiEnabled : 1;
    uint8_t privilege : 4;
#endif
} __attribute__((packed));

/** @brief initializes user management
 *
 *  @return IPMI_CC_OK for success, others for failure.
 */
ipmi_ret_t ipmiUserInit();

/** @brief The ipmi get user password layer call
 *
 *  @param[in] userName - user name
 *
 *  @return password or empty string
 */
std::string ipmiUserGetPassword(const std::string& userName);

/** @brief The IPMI call to clear password entry associated with specified
 * username
 *
 *  @param[in] userName - user name to be removed
 *
 *  @return 0 on success, non-zero otherwise.
 */
ipmi_ret_t ipmiClearUserEntryPassword(const std::string& userName);

/** @brief The IPMI call to reuse password entry for the renamed user
 *  to another one
 *
 *  @param[in] userName - user name which has to be renamed
 *  @param[in] newUserName - new user name
 *
 *  @return 0 on success, non-zero otherwise.
 */
ipmi_ret_t ipmiRenameUserEntryPassword(const std::string& userName,
                                       const std::string& newUserName);

/** @brief determines valid userId
 *
 *  @param[in] userId - user id
 *
 *  @return true if valid, false otherwise
 */
bool ipmiUserIsValidUserId(const uint8_t userId);

/** @brief determines valid privilege level
 *
 *  @param[in] priv - privilege level
 *
 *  @return true if valid, false otherwise
 */
bool ipmiUserIsValidPrivilege(const uint8_t priv);

/** @brief get user id corresponding to the user name
 *
 *  @param[in] userName - user name
 *
 *  @return userid. Will return 0xff if no user id found
 */
uint8_t ipmiUserGetUserId(const std::string& userName);

/** @brief set's user name
 *
 *  @param[in] userId - user id
 *  @param[in] userName - user name
 *
 *  @return IPMI_CC_OK for success, others for failure.
 */
ipmi_ret_t ipmiUserSetUserName(const uint8_t userId, const char* userName);

/** @brief set user password
 *
 *  @param[in] userId - user id
 *  @param[in] userPassword - New Password
 *
 *  @return IPMI_CC_OK for success, others for failure.
 */
ipmi_ret_t ipmiUserSetUserPassword(const uint8_t userId,
                                   const char* userPassword);

/** @brief set special user password (non-ipmi accounts)
 *
 *  @param[in] userName - user name
 *  @param[in] userPassword - New Password
 *
 *  @return IPMI_CC_OK for success, others for failure.
 */
ipmi_ret_t ipmiSetSpecialUserPassword(const std::string& userName,
                                      const std::string& userPassword);

/** @brief get user name
 *
 *  @param[in] userId - user id
 *  @param[out] userName - user name
 *
 *  @return IPMI_CC_OK for success, others for failure.
 */
ipmi_ret_t ipmiUserGetUserName(const uint8_t userId, std::string& userName);

/** @brief provides available fixed, max, and enabled user counts
 *
 *  @param[out] maxChUsers - max channel users
 *  @param[out] enabledUsers - enabled user count
 *  @param[out] fixedUsers - fixed user count
 *
 *  @return IPMI_CC_OK for success, others for failure.
 */
ipmi_ret_t ipmiUserGetAllCounts(uint8_t& maxChUsers, uint8_t& enabledUsers,
                                uint8_t& fixedUsers);

/** @brief function to update user enabled state
 *
 *  @param[in] userId - user id
 *..@param[in] state - state of the user to be updated, true - user enabled.
 *
 *  @return IPMI_CC_OK for success, others for failure.
 */
ipmi_ret_t ipmiUserUpdateEnabledState(const uint8_t userId, const bool& state);

/** @brief determines whether user is enabled
 *
 *  @param[in] userId - user id
 *..@param[out] state - state of the user
 *
 *  @return IPMI_CC_OK for success, others for failure.
 */
ipmi_ret_t ipmiUserCheckEnabled(const uint8_t userId, bool& state);

/** @brief provides user privilege access data
 *
 *  @param[in] userId - user id
 *  @param[in] chNum - channel number
 *  @param[out] privAccess - privilege access data
 *
 *  @return IPMI_CC_OK for success, others for failure.
 */
ipmi_ret_t ipmiUserGetPrivilegeAccess(const uint8_t userId, const uint8_t chNum,
                                      PrivAccess& privAccess);

/** @brief sets user privilege access data
 *
 *  @param[in] userId - user id
 *  @param[in] chNum - channel number
 *  @param[in] privAccess - privilege access data
 *  @param[in] otherPrivUpdate - flags to indicate other fields update
 *
 *  @return IPMI_CC_OK for success, others for failure.
 */
ipmi_ret_t ipmiUserSetPrivilegeAccess(const uint8_t userId, const uint8_t chNum,
                                      const PrivAccess& privAccess,
                                      const bool& otherPrivUpdate);

/** @brief check for user pam authentication. This is to determine, whether user
 * is already locked out for failed login attempt
 *
 *  @param[in] username - username
 *  @param[in] password - password
 *
 *  @return status
 */
bool ipmiUserPamAuthenticate(std::string_view userName,
                             std::string_view userPassword);

} // namespace ipmi
