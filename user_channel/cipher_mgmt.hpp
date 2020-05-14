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

#include <ipmid/api-types.hpp>
#include <ipmid/message/types.hpp>
#include <map>
#include <nlohmann/json.hpp>

namespace ipmi
{
static const std::string csPrivDefaultFileName =
    "/usr/share/ipmi-providers/cs_privilege_levels.json";

static const std::string csPrivFileName =
    "/var/lib/ipmi/cs_privilege_levels.json";

static const size_t maxCSRecords = 16;

using ChannelNumCipherIDPair = std::pair<uint8_t, uint8_t>;
using privMap = std::map<ChannelNumCipherIDPair, uint4_t>;

constexpr uint8_t PRIVILEGE_ERROR = 0xFF;

/** @class CipherConfig
 *  @brief Class to provide cipher suite functionalities
 */
class CipherConfig
{
  public:
    ~CipherConfig() = default;
    explicit CipherConfig(const std::string& csFileName,
                          const std::string& csDefaultFileName);
    CipherConfig() = delete;

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
    ipmi::Cc getCSPrivilegeLevels(
        uint8_t chNum, std::array<uint4_t, maxCSRecords>& csPrivilegeLevels);

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
    ipmi::Cc setCSPrivilegeLevels(
        uint8_t chNum,
        const std::array<uint4_t, maxCSRecords>& csPrivilegeLevels);

    /** @brief function to get highest level matching proposed algorithm
     *
     */
    uint8_t getHighestLevelMatchProposedAlgorithm(
        const uint8_t chNum, const std::string& cipherListFileName =
                                 "/usr/share/ipmi-providers/cipher_list.json");

  private:
    std::string cipherSuitePrivFileName, cipherSuiteDefaultPrivFileName;

    privMap csPrivilegeMap;

    std::time_t fileLastUpdatedTime;

    /** @brief function to read json config file
     *
     *  @return nlohmann::json object
     */
    nlohmann::json readCSPrivilegeLevels(const std::string& csFileName);

    /** @brief function to write json config file
     *
     *  @param[in] jsonData - json object
     *
     *  @return 0 for success, -errno for failure.
     */
    int writeCSPrivilegeLevels(const nlohmann::json& jsonData);

    /** @brief convert to cipher suite privilege from string to value
     *
     *  @param[in] value - privilege value
     *
     *  @return cipher suite privilege index
     */
    uint4_t convertToPrivLimitIndex(const std::string& value);

    /** @brief function to convert privilege value to string
     *
     *  @param[in] value - privilege value
     *
     *  @return privilege in string
     */
    std::string convertToPrivLimitString(const uint4_t& value);

    /** @brief function to load CS Privilege Levels from json file/files to map
     *
     */
    void loadCSPrivilegesToMap();

    /** @brief function to update CS privileges map from json object data,
     * jsonData
     *
     */
    void updateCSPrivilegesMap(const nlohmann::json& jsonData);

    /** @brief function to retrieve last modification time for the named file
     *
     *  @param[in] fileName - the name of the file for which to acquire
     *  timestamp data
     *
     *  @return time the file was last modified
     */
    std::time_t getUpdatedFileTime(const std::string& fileName);

    /** @brief function to check and reload cipher suite data
     *
     *  @return 0 for success, -errno for failure.
     */
    int checkAndReloadData();
};

/** @brief function to create static CipherConfig object
 *
 *  @param[in] csFileName - user setting cipher suite privilege file name
 *  @param[in] csDefaultFileName - default cipher suite privilege file name
 *
 *  @return static CipherConfig object
 */
CipherConfig& getCipherConfigObject(const std::string& csFileName,
                                    const std::string& csDefaultFileName);
} // namespace ipmi
