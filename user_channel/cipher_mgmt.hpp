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

    const std::string privAdmin = "PrivAdmin";

    const uint8_t maxCSRecords = 16;
    /** @brief function to read json config file
     *
     *  @return Json object
     */
    Json readCSPrivilegeLevels();

    /** @brief function to write json config file
     *
     *  @param[in] jsonData - json object
     *
     *  @return 0 for success, -errno for failure.
     */
    int32_t writeCSPrivilegeLevels(const Json& jsonData);

    /** @brief function to initialise CS Privilege Levels json config file
     *
     */
    void initCSPrivilegeLevelsPersistData();
};

CipherConfig& getCipherConfigObject(const std::string& csFileName);
} // namespace ipmi
