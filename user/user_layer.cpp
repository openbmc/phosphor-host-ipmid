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
static ipmi::PasswdMgr passwdMgr;

ipmi_ret_t ipmi_user_get_password(const std::string& userName,
                                  std::string& password)
{
    password = passwdMgr.getPasswdByUserName(userName);
    return IPMI_CC_OK;
}

ipmi_ret_t ipmi_user_clear_password(const std::string& userName)
{
    passwdMgr.clearUserEntry(userName);
    return IPMI_CC_OK;
}
