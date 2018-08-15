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
#include <string>
#include <host-ipmid/ipmid-api.h>

namespace ipmi
{

enum class EChannelID : uint8_t
{
    chanIpmb = 0x00,      // Channel 0x00
    chanLan1 = 0x01,      // Channel 0x01
    chanLan2 = 0x02,      // Channel 0x02
    chanLan3 = 0x03,      // Channel 0x03
    chanEmp = 0x04,       // Channel 0x04
    chanIcmb = 0x05,      // Channel 0x05
    chanSmlink0 = 0x06,   // Channel 0x06
    chanSmm = 0x07,       // Channel 0x07
    chanIntrabmc = 0x08,  // Channel 0x08
    chanSipmb = 0x09,     // Channel 0x09       (Secondary IPMB)
    chanPcie = 0x0A,      // Channel 0x0A       (PCIE slots)
    chanBReserved = 0x0B, // Channel 0x0B       (reserved)
    chanInternal = 0x0C,  // Channel 0x0C
    chanDReserved = 0x0D, // Channel 0x0D       (reserved)
    chanSelf = 0x0E,      // Channel 0x0E       (refers to self)
    chanSms = 0x0F        // Channel 0x0F
};

struct PrivAccess
{
    uint8_t privilege : 4;
    uint8_t ipmiEnabled : 1;
    uint8_t linkAuthEnabled : 1;
    uint8_t accessCallback : 1;
    uint8_t reserved : 1;
} __attribute__((packed));

/** @brief initializes user management
 *
 *  @return IPMI_CC_OK for success, others for failure.
 */
ipmi_ret_t ipmiUserInit();

/** @brief The ipmi get user password layer call
 *
 *  @param[in] userName
 *  @param[out] password
 *
 *  @return 0 on success, non-zero otherwise.
 */
ipmi_ret_t ipmiUserGetPassword(const std::string& userName,
                             std::string& password);

/** @brief The IPMI call to clear password entry associated with specified username
 *
 *  @param[in] userName
 *
 *  @return 0 on success, non-zero otherwise.
 */
ipmi_ret_t ipmiUserClearPassword(const std::string& userName);

/** @brief determines valid userId
 *
 *  @param[in] user id
 *
 *  @return true if valid, false otherwise
 */
bool ipmiUserIsValidUserId(const uint8_t &userId);

/** @brief determines valid channel
 *
 *  @param[in] channel number
 *
 *  @return true if valid, false otherwise
 */
bool ipmiUserIsValidChannel(const uint8_t &chNum);

/** @brief determines valid privilege level
 *
 *  @param[in] privilege level
 *
 *  @return true if valid, false otherwise
 */
bool ipmiUserIsValidPrivilege(const uint8_t &priv);

/** @brief set's user name
 *
 *  @param[in] user id
 *  @param[in] user name
 *
 *  @return IPMI_CC_OK for success, others for failure.
 */
ipmi_ret_t ipmiUserSetUserName(const uint8_t &userId, const char *userName);

/** @brief get user name
 *
 *  @param[in] user id
 *  @param[out] user name
 *
 *  @return IPMI_CC_OK for success, others for failure.
 */
ipmi_ret_t ipmiUserGetUserName(const uint8_t &userId, std::string &userName);

/** @brief provides available fixed, max, and enabled user counts
 *
 *  @param[out] max channel users
 *  @param[out] enabled user count
 *  @param[out] fixed user count
 *
 *  @return IPMI_CC_OK for success, others for failure.
 */
ipmi_ret_t ipmiUserGetMaxCounts(uint8_t &maxChUsers, uint8_t &enabledUsers,
                                uint8_t &fixedUsers);

/** @brief determines whether user is enabled
 *
 *  @param[in] user id
 *..@param[out] state of the user
 *
 *  @return IPMI_CC_OK for success, others for failure.
 */
ipmi_ret_t ipmiUserCheckEnabled(const uint8_t &userId, bool &state);

/** @brief provides user privilege access data
 *
 *  @param[in] user id
 *  @param[in] channel number
 *  @param[out] privilege access data ([0:3] - privilege, [4] - ipmi enabled,
 * [5] -link auth enabled, [6] -access callback, [7] - reserved.
 *  @return IPMI_CC_OK for success, others for failure.
 */
ipmi_ret_t ipmiUserGetPrivilegeAccess(const uint8_t &userId,
                                      const uint8_t &chNum,
                                      PrivAccess &privAccess);

/** @brief sets user privilege access data
 *
 *  @param[in] user id
 *  @param[in] channel number
 *  @param[in] privilege access data ([0:3] - privilege, [4] - ipmi enabled, [5]
 *  @param[in] update other fields in privilege access
 *  @return IPMI_CC_OK for success, others for failure.
 */
ipmi_ret_t ipmiUserSetPrivilegeAccess(const uint8_t &userId,
                                      const uint8_t &chNum,
                                      const PrivAccess &privAccess,
                                      const bool &otherPrivUpdate);

} // namespace ipmi
