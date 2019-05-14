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

#include "cipher_mgmt.hpp"

#include <experimental/filesystem>
#include <fstream>
#include <phosphor-logging/log.hpp>

namespace ipmi
{

using namespace phosphor::logging;
namespace fs = std::experimental::filesystem;

static constexpr const char* cipherSuitePrivFileName =
    "/var/lib/ipmi/cs_privilege_levels.json";

static constexpr const char* privAdmin = "PrivAdmin";

static constexpr uint8_t maxCSRecords = 16;

CipherConfig& getCipherConfigObject()
{
    static CipherConfig cipherConfig;
    return cipherConfig;
}

CipherConfig::~CipherConfig()
{
    // Nothing to do here as of now
}

CipherConfig::CipherConfig()
{
    if (!fs::exists(cipherSuitePrivFileName))
    {
        log<level::DEBUG>(
            "CS privilege levels file does not exist. Initialising...");
        initPrivilegeLevelsPersistData();
    }
}

Json CipherConfig::readJsonFile(const std::string& configFile)
{
    std::ifstream jsonFile(configFile);
    if (!jsonFile.good())
    {
        log<level::ERR>("JSON file not found");
        return nullptr;
    }

    Json data = nullptr;
    try
    {
        data = Json::parse(jsonFile, nullptr, false);
    }
    catch (Json::parse_error& e)
    {
        log<level::DEBUG>("Corrupted channel config.",
                          entry("MSG: %s", e.what()));
        throw std::runtime_error("Corrupted channel config file");
    }

    return data;
}

int CipherConfig::writeJsonFile(const std::string& configFile,
                                const Json& jsonData)
{
    std::ofstream jsonFile(configFile);
    if (!jsonFile.good())
    {
        log<level::ERR>("JSON file not found");
        return -EIO;
    }

    // Write JSON to file
    jsonFile << jsonData;

    jsonFile.flush();
    return 0;
}

void CipherConfig::initPrivilegeLevelsPersistData()
{
    Json initData;
    std::ofstream csPrivilegeLevelsFile;
    uint8_t chNum, csNum;

    csPrivilegeLevelsFile.open(cipherSuitePrivFileName);

    for (chNum = 0; chNum < ipmi::maxIpmiChannels; chNum++)
    {
        Json privData;

        std::string chKey = "Channel" + std::to_string(chNum);
        for (csNum = 0; csNum < maxCSRecords; csNum++)
        {
            std::string csKey = "CipherID" + std::to_string(csNum);
            // By default, provide Admin privileges for all Cipher Suites,
            // across all channels
            privData[csKey] = privAdmin;
        }
        initData[chKey] = privData;
    }

    if (writeJsonFile(cipherSuitePrivFileName, initData) != 0)
    {
        log<level::ERR>(
            "Error initialising CipherSuite Privilege Levels file.");
    }

    csPrivilegeLevelsFile.close();

    log<level::DEBUG>("Successfully initialised CipherSuite Privilege Levels "
                      "data initialization.");
    return;
}

} // namespace ipmi
