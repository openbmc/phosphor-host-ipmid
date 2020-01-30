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

constexpr size_t lanParamCipherSuitePrivilegeLevelsSize = 9;

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

    /** @brief function to get cipher suite privileges from config file
     *
     *  @param[in] chNum - channel number for which we want to get cipher suite
     * privilege levels
     *
     *  @param[in] csPrivilegeLevels - gets filled by cipher suite privilege
     * levels
     *
     *  @return 0 for success, non zero value for failure
     */
    uint8_t getCSPrivilegeLevels(
        uint8_t chNum,
        std::array<uint8_t, lanParamCipherSuitePrivilegeLevelsSize>&
            csPrivilegeLevels);

    /** @brief function to set/update cipher suite privileges in config file
     *
     *  @param[in] chNum - channel number for which we want to update cipher
     * suite privilege levels
     *
     *  @param[in] csPrivilegeLevels - cipher suite privilege levels to update
     * in config file
     *
     *  @return 0 for success, non zero value for failure
     */
    uint8_t setCSPrivilegeLevels(
        uint8_t chNum,
        const std::array<uint8_t, lanParamCipherSuitePrivilegeLevelsSize>&
            csPrivilegeLevels);

    /** @brief function to get highest level matching proposed algorithm
     *
     */
    uint8_t getHighestLevelMatchPropAlgo(uint8_t chNum);

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
