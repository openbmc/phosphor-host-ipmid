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
#include <host-ipmid/ipmid-api.h>

#include <string>

namespace ipmi
{
/** @brief The ipmi get user password layer call
 *
 *  @param[in] userName
 *
 *  @return password or empty string
 */
std::string ipmiUserGetPassword(const std::string& userName);

/** @brief The IPMI call to clear password entry associated with specified
 * username
 *
 *  @param[in] userName
 *
 *  @return 0 on success, non-zero otherwise.
 */
ipmi_ret_t ipmiClearUserEntryPassword(const std::string& userName);

/** @brief The IPMI call to reuse password entry for the renamed user
 *  to another one
 *
 *  @param[in] userName
 *  @param[in] newUserName
 *
 *  @return 0 on success, non-zero otherwise.
 */
ipmi_ret_t ipmiRenameUserEntryPassword(const std::string& userName,
                                       const std::string& newUserName);

// TODO: Define required user layer API Call's which user layer shared library
// must implement.
} // namespace ipmi
