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

static std::array<std::string, PRIVILEGE_OEM + 1> privList = {
    "priv-unspecified", "priv-callback", "priv-user",
    "priv-operator",    "priv-admin",    "priv-oem"};

CipherConfig& getCipherConfigObject(const std::string& csFileName)
{
    static CipherConfig cipherConfig(csFileName);
    return cipherConfig;
}

CipherConfig::CipherConfig(const std::string& csFileName) :
    cipherSuitePrivFileName(csFileName)
{
    if (!fs::exists(cipherSuitePrivFileName))
    {
        log<level::INFO>("CS privilege levels user settings file does not "
                         "exist. Switching to default file...");
        cipherSuitePrivFileName = csPrivDefaultFileName;
    }
    loadCSPrivilegesToMap();
}

void CipherConfig::loadCSPrivilegesToMap()
{
    if (!fs::exists(csPrivDefaultFileName))
    {
        log<level::ERR>("CS privilege levels default file does not exist...");
    }
    else
    {
        Json data = readCSPrivilegeLevels(csPrivDefaultFileName);

        // load default privileges
        updateCSPrivilegesMap(data);

        // check for user-saved privileges
        if (fs::exists(csPrivFileName))
        {
            data = readCSPrivilegeLevels(csPrivFileName);
            if (data != nullptr)
            {
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
    auto iter = std::find(privList.begin(), privList.end(), value);
    if (iter == privList.end())
    {
        log<level::ERR>("Invalid privilege.",
                        entry("PRIV_STR=%s", value.c_str()));
        return ccUnspecifiedError;
    }

    return static_cast<uint4_t>(std::distance(privList.begin(), iter));
}

std::string CipherConfig::convertToPrivLimitString(const uint4_t value)
{
    return privList.at(static_cast<uint8_t>(value));
}

uint8_t CipherConfig::getCSPrivilegeLevels(
    uint8_t chNum, std::array<uint4_t, maxCSRecords>& csPrivilegeLevels)
{
    if (!isValidChannel(chNum))
    {
        log<level::ERR>("Invalid channel number", entry("CHANNEL=%u", chNum));
        return ccInvalidFieldRequest;
    }

    for (uint8_t csNum = 0; csNum < maxCSRecords; ++csNum)
    {
        csPrivilegeLevels[csNum] = csPrivilegeMap[{chNum, csNum}];
    }
    return ccSuccess;
}

uint8_t CipherConfig::setCSPrivilegeLevels(
    uint8_t chNum, const std::array<uint4_t, maxCSRecords>& requestData)
{
    if (!isValidChannel(chNum))
    {
        log<level::ERR>("Invalid channel number", entry("CHANNEL=%u", chNum));
        return ccInvalidFieldRequest;
    }

    Json jsonData;
    if (!fs::exists(csPrivFileName))
    {
        log<level::INFO>("CS privilege levels user settings file does not "
                         "exist. Creating...");
        cipherSuitePrivFileName = csPrivFileName;
    }
    else
    {
        jsonData = readCSPrivilegeLevels(csPrivFileName);
        if (jsonData == nullptr)
        {
            return ccUnspecifiedError;
        }
    }

    Json privData;
    std::string csKey;
    constexpr uint8_t requestDataMask = 0x0F;
    constexpr uint8_t dataMaxValue = 0x05;

    for (uint8_t csNum = 0; csNum < maxCSRecords; ++csNum)
    {
        csKey = "CipherID" + std::to_string(csNum);

        if ((static_cast<uint8_t>(requestData[csNum]) & requestDataMask) >
            dataMaxValue)
        {
            return ccInvalidFieldRequest;
        }
        privData[csKey] =
            convertToPrivLimitString(static_cast<uint8_t>(requestData[csNum]));
    }

    std::string chKey = "Channel" + std::to_string(chNum);

    jsonData[chKey] = privData;

    if (writeCSPrivilegeLevels(jsonData))
    {
        log<level::ERR>("Error in setting CS Privilege Levels.");
        return ccUnspecifiedError;
    }

    updateCSPrivilegesMap(jsonData);
    return ccSuccess;
}

} // namespace ipmi
