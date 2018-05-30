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
#include "user_mgmt.hpp"

namespace ipmi
{
bool ipmi_user_is_valid_user_id(const uint8_t &user_id)
{
    return UserAccess::isValidUserId(user_id);
}

bool ipmi_user_is_valid_channel(const uint8_t &ch_num)
{
    return UserAccess::isValidChannel(ch_num);
}

bool ipmi_user_is_valid_privilege(const uint8_t &priv)
{
    return UserAccess::isValidPrivilege(priv);
}

ipmi_ret_t ipmi_user_set_user_name(const uint8_t &user_id,
                                   const char *user_name)
{
    return getUserAccessObject().setUserName(user_id, user_name);
}

ipmi_ret_t ipmi_user_get_user_name(const uint8_t &user_id,
                                   std::string &user_name)
{
    return getUserAccessObject().getUserName(user_id, user_name);
}

ipmi_ret_t ipmi_user_get_max_counts(uint8_t &max_ch_users,
                                    uint8_t &enabled_users,
                                    uint8_t &fixed_users)
{
    max_ch_users = IPMI_MAX_USERS;
    userdata_t *userData = getUserAccessObject().getUserDataPtr();
    enabled_users = 0;
    fixed_users = 0;
    for (size_t count = 1; count <= IPMI_MAX_USERS; ++count)
    {
        if (userData->user[count].userEnabled)
        {
            enabled_users++;
        }
        if (userData->user[count].fixedUserName)
        {
            fixed_users++;
        }
    }
    return IPMI_CC_OK;
}

ipmi_ret_t ipmi_user_check_enabled(const uint8_t &user_id, bool &state)
{
    if (!UserAccess::isValidUserId(user_id))
    {
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }
    userdata_t *userData = getUserAccessObject().getUserDataPtr();
    state = (userData->user[user_id].userEnabled == 1) ? true : false;
    return IPMI_CC_OK;
}

ipmi_ret_t ipmi_user_get_privilege_access(const uint8_t &user_id,
                                          const uint8_t &ch_num,
                                          user_priv_access_t &priv_access)
{

    if (!UserAccess::isValidChannel(ch_num))
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    if (!UserAccess::isValidUserId(user_id))
    {
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }
    userdata_t *userData = getUserAccessObject().getUserDataPtr();
    std::copy((uint8_t *)&(userData->user[user_id].userPrivAccess[ch_num]),
              ((uint8_t *)&(userData->user[user_id].userPrivAccess[ch_num])) +
                  sizeof(priv_access),
              (uint8_t *)&priv_access);
    return IPMI_CC_OK;
}

ipmi_ret_t ipmi_user_set_privilege_access(const uint8_t &user_id,
                                          const uint8_t &ch_num,
                                          const user_priv_access_t &priv_access,
                                          const uint8_t &flags)
{
    return getUserAccessObject().setUserPrivilegeAccess(user_id, ch_num,
                                                        priv_access, flags);
}

} // namespace ipmi
