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

static constexpr uint8_t MAX_IPMI_20_PASSWORD_SIZE = 20;
static constexpr uint8_t MAX_IPMI_15_PASSWORD_SIZE = 16;
static constexpr uint8_t DISABLE_USER = 0x00;
static constexpr uint8_t ENABLE_USER = 0x01;
static constexpr uint8_t SET_PASSWORD = 0x02;
static constexpr uint8_t TEST_PASSWORD = 0x03;

static constexpr uint8_t INVALID_USER_ID = 0x1;
static constexpr uint8_t INVALID_CH_ID = 0x1;
static constexpr uint8_t INVALID_USER_NAME = 0x1;

typedef enum {
    CHAN_IPMB,       // Channel 0x00
    CHAN_LAN1,       // Channel 0x01
    CHAN_LAN2,       // Channel 0x02
    CHAN_LAN3,       // Channel 0x03
    CHAN_EMP,        // Channel 0x04
    CHAN_ICMB,       // Channel 0x05
    CHAN_SMLINK0,    // Channel 0x06
    CHAN_SMM,        // Channel 0x07
    CHAN_INTRABMC,   // Channel 0x08
    CHAN_SIPMB,      // Channel 0x09       (Secondary IPMB)
    CHAN_PCIE,       // Channel 0x0A       (PCIE slots)
    CHAN_B_RESERVED, // Channel 0x0B       (reserved)
    CHAN_INTERNAL,   // Channel 0x0C
    CHAN_D_RESERVED, // Channel 0x0D       (reserved)
    CHAN_SELF,       // Channel 0x0E       (refers to self)
    CHAN_SMS         // Channel 0x0F
} EChannelID;

struct user_priv_access_t
{
    uint8_t privilege : 4;
    uint8_t ipmi_enabled : 1;
    uint8_t link_auth_enabled : 1;
    uint8_t access_callback : 1;
    uint8_t reserved : 1;
} __attribute__((packed));

/** @brief determines valid user_id
 *
 *  @param[in] user id
 *
 *  @return true if valid, false otherwise
 */
bool ipmi_user_is_valid_user_id(const uint8_t &user_id);

/** @brief determines valid channel
 *
 *  @param[in] channel number
 *
 *  @return true if valid, false otherwise
 */
bool ipmi_user_is_valid_channel(const uint8_t &ch_num);

/** @brief set's user name
 *
 *  @param[in] user_id
 *  @param[in] user_name
 *
 *  @return IPMI_CC_OK for success, others for failure.
 */
ipmi_ret_t ipmi_user_set_user_name(const uint8_t &user_id,
                                   const char *user_name);

/** @brief get user name
 *
 *  @param[in] user_id
 *  @param[out] user_name
 *
 *  @return IPMI_CC_OK for success, others for failure.
 */
ipmi_ret_t ipmi_user_get_user_name(const uint8_t &user_id,
                                   std::string &user_name);

/** @brief provides available fixed, max, and enabled user counts
 *
 *  @param[out] max channel users
 *  @param[out] enabled user count
 *  @param[out] fixed user count
 *
 *  @return IPMI_CC_OK for success, others for failure.
 */
ipmi_ret_t ipmi_user_get_max_counts(uint8_t &max_ch_users,
                                    uint8_t &enabled_users,
                                    uint8_t &fixed_users);

/** @brief determines whether user is enabled
 *
 *  @param[in] user id
 *..@param[out] state of the user
 *
 *  @return IPMI_CC_OK for success, others for failure.
 */
ipmi_ret_t ipmi_user_check_enabled(const uint8_t &user_id, bool &state);

/** @brief provides user privilege access data
 *
 *  @param[in] user id
 *  @param[in] channel number
 *
 *  @return privilege access data ([0:3] - privilege, [4] - ipmi enabled, [5]
 * -link auth enabled, [6] -access callback, [7] - reserved.
 */
user_priv_access_t ipmi_user_get_privilege_access(const uint8_t &user_id,
                                                  const uint8_t &ch_num);

// TODO: Define required user layer API Call's which user layer shared library
// must implement.
} // namespace ipmi
