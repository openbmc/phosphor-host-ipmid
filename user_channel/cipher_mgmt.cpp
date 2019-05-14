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

Json CipherConfig::readPrivilegeLevelsJsonFile()
{
    std::ifstream jsonFile(cipherSuitePrivFileName);
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
        log<level::DEBUG>(
            "Corrupted cipher suite privilege levels config file.",
            entry("MSG: %s", e.what()));
        throw std::runtime_error(
            "Corrupted cipher suite privielge levels config file");
    }

    return data;
}

int CipherConfig::writePrivilegeLevelsJsonFile(const Json& jsonData)
{
    std::ofstream jsonFile;

    jsonFile.open(cipherSuitePrivFileName);

    if (!jsonFile.good())
    {
        log<level::ERR>("JSON file not found");
        return -EIO;
    }

    // Write JSON to file
    jsonFile << jsonData;

    jsonFile.flush();

    jsonFile.close();
    return 0;
}

void CipherConfig::initPrivilegeLevelsPersistData()
{
    Json initData;
    uint8_t chNum, csNum;

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

    if (writePrivilegeLevelsJsonFile(initData) != 0)
    {
        log<level::ERR>(
            "Error initialising CipherSuite Privilege Levels file.");
    }

    log<level::DEBUG>("Successfully initialised CipherSuite Privilege Levels "
                      "data initialization.");
    return;
}

} // namespace ipmi
