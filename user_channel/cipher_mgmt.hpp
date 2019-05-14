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
#include "channel_layer.hpp"

#include <nlohmann/json.hpp>

namespace ipmi
{

using Json = nlohmann::json;

class CipherConfig;

CipherConfig& getCipherConfigObject();

class CipherConfig
{
  public:
    ~CipherConfig();
    CipherConfig();

  private:
    // CS Privilege levels filename
    const char* cipherSuitePrivFileName =
        "/var/lib/ipmi/cs_privilege_levels.json";

    const char* privAdmin = "PrivAdmin";

    const uint8_t maxCSRecords = 16;
    /** @brief function to read json config file
     *
     *  @param[in] configFile - configuration file name
     *
     *  @return Json object
     */
    Json readPrivilegeLevelsJsonFile(void);

    /** @brief function to write json config file
     *
     *  @param[in] configFile - configuration file name
     *  @param[in] jsonData - json object
     *
     *  @return 0 for success, -errno for failure.
     */
    int writePrivilegeLevelsJsonFile(const Json& jsonData);

    /** @brief function to initialise CS Privilege Levels json config file
     *
     */
    void initPrivilegeLevelsPersistData();
};

} // namespace ipmi
