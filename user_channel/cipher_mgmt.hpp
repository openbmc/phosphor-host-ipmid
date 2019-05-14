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

#include <map>
#include <nlohmann/json.hpp>

namespace ipmi
{
using Json = nlohmann::json;

const std::string csPrivDefaultFileName =
    "/usr/share/ipmi-providers/cs_privilege_levels.json";

const std::string csPrivFileName = "/var/lib/ipmi/cs_privilege_levels.json";

/** @class CipherConfig
 *  @brief Class to provide cipher suite functionalities
 */
class CipherConfig
{
  public:
    ~CipherConfig() = default;
    CipherConfig(const std::string& csFileName);

  private:
    std::string cipherSuitePrivFileName;

    const uint8_t maxCSRecords = 16;

    std::map<std::pair<uint8_t, uint8_t>, uint8_t> csPrivilegeMap;

    /** @brief function to read json config file
     *
     *  @return Json object
     */
    Json readCSPrivilegeLevels(const std::string& csFileName);

    /** @brief function to write json config file
     *
     *  @param[in] jsonData - json object
     *
     *  @return 0 for success, -errno for failure.
     */
    int writeCSPrivilegeLevels(const Json& jsonData);
    /** @brief convert to cipher suite privilege from string to value
     *
     *  @param[in] value - privilege value
     *
     *  @return cipher suite privilege index
     */
    uint8_t convertToPrivLimitIndex(const std::string& value);

    /** @brief function to convert privilege value to string
     *
     *  @param[in] value - privilege value
     *
     *  @return privilege in string
     */
    std::string convertToPrivLimitString(const uint8_t value);

    /** @brief function to load CS Privilege Levels from json file/files to map
     *
     */
    void loadCSPrivilegesToMap();

    /** @brief function to update CS privileges in map
     *
     */
    void updateCSPrivilegesMap(const Json& jsonData);
};

CipherConfig& getCipherConfigObject(const std::string& csFileName);
} // namespace ipmi
