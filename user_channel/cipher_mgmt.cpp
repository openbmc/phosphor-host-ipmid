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

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <include/ipmid/api-types.hpp>
#include <phosphor-logging/log.hpp>

namespace ipmi
{

using namespace phosphor::logging;
using Json = nlohmann::json;
namespace fs = std::filesystem;

CipherConfig& getCipherConfigObject(const std::string& csFileName,
                                    const std::string& csDefaultFileName)
{
    static CipherConfig cipherConfig(csFileName, csDefaultFileName);
    return cipherConfig;
}

CipherConfig::CipherConfig(const std::string& csFileName,
                           const std::string& csDefaultFileName) :
    cipherSuitePrivFileName(csFileName),
    cipherSuiteDefaultPrivFileName(csDefaultFileName)
{
    loadCSPrivilegesToMap();
}

void CipherConfig::loadCSPrivilegesToMap()
{
    if (!fs::exists(cipherSuiteDefaultPrivFileName))
    {
        log<level::ERR>("CS privilege levels default file does not exist...");
    }
    else
    {
        // read default privileges
        Json data = readCSPrivilegeLevels(cipherSuiteDefaultPrivFileName);

        // load default privileges
        updateCSPrivilegesMap(data);

        // check for user-saved privileges
        if (fs::exists(cipherSuitePrivFileName))
        {
            data = readCSPrivilegeLevels(cipherSuitePrivFileName);
            if (data != nullptr)
            {
                // update map with user-saved privileges by merging (overriding)
                // values from the defaults
                updateCSPrivilegesMap(data);
            }
        }
    }
}

void CipherConfig::updateCSPrivilegesMap(const Json& jsonData)
{
    for (uint8_t chNum = 0; chNum < ipmi::maxIpmiChannels; chNum++)
    {
        std::string chKey = "Channel" + std::to_string(chNum);
        for (uint8_t csNum = 0; csNum < maxCSRecords; csNum++)
        {
            auto csKey = "CipherID" + std::to_string(csNum);

            if (jsonData.find(chKey) != jsonData.end())
            {
                csPrivilegeMap[{chNum, csNum}] = convertToPrivLimitIndex(
                    static_cast<std::string>(jsonData[chKey][csKey]));
            }
        }
    }
}

Json CipherConfig::readCSPrivilegeLevels(const std::string& csFileName)
{
    std::ifstream jsonFile(csFileName);
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
        log<level::ERR>("Corrupted cipher suite privilege levels config file.",
                        entry("MSG: %s", e.what()));
    }

    return data;
}

int CipherConfig::writeCSPrivilegeLevels(const Json& jsonData)
{
    std::string tmpFile =
        static_cast<std::string>(cipherSuitePrivFileName) + "_tmpXXXXXX";

    char tmpRandomFile[tmpFile.length() + 1];
    strncpy(tmpRandomFile, tmpFile.c_str(), tmpFile.length() + 1);

    int fd = mkstemp(tmpRandomFile);
    fchmod(fd, 0644);

    if (fd < 0)
    {
        log<level::ERR>("Error opening CS privilege level config file",
                        entry("FILE_NAME=%s", tmpFile.c_str()));
        return -EIO;
    }
    const auto& writeData = jsonData.dump();
    if (write(fd, writeData.c_str(), writeData.size()) !=
        static_cast<ssize_t>(writeData.size()))
    {
        close(fd);
        log<level::ERR>("Error writing CS privilege level config file",
                        entry("FILE_NAME=%s", tmpFile.c_str()));
        unlink(tmpRandomFile);
        return -EIO;
    }
    close(fd);

    if (std::rename(tmpRandomFile, cipherSuitePrivFileName.c_str()))
    {
        log<level::ERR>("Error renaming CS privilege level config file",
                        entry("FILE_NAME=%s", tmpFile.c_str()));
        unlink(tmpRandomFile);
        return -EIO;
    }

    return 0;
}

uint4_t CipherConfig::convertToPrivLimitIndex(const std::string& value)
{
    auto iter = std::find(ipmi::privList.begin(), ipmi::privList.end(), value);
    if (iter == privList.end())
    {
        log<level::ERR>("Invalid privilege.",
                        entry("PRIV_STR=%s", value.c_str()));
        return ccUnspecifiedError;
    }

    return static_cast<uint4_t>(std::distance(ipmi::privList.begin(), iter));
}

std::string CipherConfig::convertToPrivLimitString(const uint4_t& value)
{
    return ipmi::privList.at(static_cast<size_t>(value));
}

} // namespace ipmi
