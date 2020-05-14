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

#include "channel_layer.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
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

ipmi::Cc CipherConfig::getCSPrivilegeLevels(
    uint8_t chNum, std::array<uint4_t, maxCSRecords>& csPrivilegeLevels)
{
    if (!isValidChannel(chNum))
    {
        log<level::ERR>("Invalid channel number", entry("CHANNEL=%u", chNum));
        return ccInvalidFieldRequest;
    }

    for (size_t csNum = 0; csNum < maxCSRecords; ++csNum)
    {
        csPrivilegeLevels[csNum] = csPrivilegeMap[{chNum, csNum}];
    }
    return ccSuccess;
}

ipmi::Cc CipherConfig::setCSPrivilegeLevels(
    uint8_t chNum, const std::array<uint4_t, maxCSRecords>& requestData)
{
    if (!isValidChannel(chNum))
    {
        log<level::ERR>("Invalid channel number", entry("CHANNEL=%u", chNum));
        return ccInvalidFieldRequest;
    }

    Json jsonData;
    if (!fs::exists(cipherSuitePrivFileName))
    {
        log<level::INFO>("CS privilege levels user settings file does not "
                         "exist. Creating...");
    }
    else
    {
        jsonData = readCSPrivilegeLevels(cipherSuitePrivFileName);
        if (jsonData == nullptr)
        {
            return ccUnspecifiedError;
        }
    }

    Json privData;
    std::string csKey;
    constexpr auto privMaxValue = static_cast<uint8_t>(ipmi::Privilege::Oem);
    for (size_t csNum = 0; csNum < maxCSRecords; ++csNum)
    {
        csKey = "CipherID" + std::to_string(csNum);
        auto priv = static_cast<uint8_t>(requestData[csNum]);

        if (priv > privMaxValue)
        {
            return ccInvalidFieldRequest;
        }
        privData[csKey] = convertToPrivLimitString(priv);
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

std::string CipherConfig::getCipherID(uint8_t auth, uint8_t integrity,
                                      uint8_t confidentiality)
{
    std::map<uint8_t, std::array<uint8_t, 3>> cipherSuiteIDS = {
        {0, {0, 0, 0}},  {1, {0, 1, 0}},  {2, {1, 1, 0}},  {3, {1, 1, 1}},
        {4, {1, 1, 2}},  {5, {1, 1, 3}},  {6, {2, 0, 0}},  {7, {2, 2, 0}},
        {8, {2, 2, 1}},  {9, {2, 2, 2}},  {10, {2, 2, 3}}, {11, {2, 3, 0}},
        {12, {2, 3, 1}}, {13, {2, 3, 2}}, {14, {2, 3, 3}}, {15, {3, 0, 0}},
        {16, {3, 4, 0}}, {17, {3, 4, 1}}, {18, {3, 4, 2}}, {19, {3, 4, 3}},
    };

    for (auto it = cipherSuiteIDS.begin(); it != cipherSuiteIDS.end(); ++it)
    {
        if ((it->second[0] == auth) && (it->second[1] == integrity) &&
            (it->second[2] == confidentiality))
        {
            return ("CipherID" + std::to_string(it->first));
        }
    }

    return "Invalid";
}

uint8_t CipherConfig::getHighestLevelMatchProposedAlgorithm(
    const uint8_t chNum, uint8_t auth, uint8_t integrity,
    uint8_t confidentiality)
{
    uint8_t priv = 0x00;
    std::string cipherID;
    std::string channelNum = "Channel" + std::to_string(chNum);
    std::string configFile;

    if (!isValidChannel(chNum))
    {
        log<level::ERR>("Invalid channel number", entry("CHANNEL=%u", chNum));
        return PRIVILEGE_ERROR;
    }

    if (fs::exists(cipherSuitePrivFileName))
    {
        configFile = "/usr/share/ipmi-providers/cs_privilege_levels.json";
    }
    else
    {
        configFile =
            "/usr/share/ipmi-providers/cs_privilege_levels_default.json";
    }

    Json data = nullptr;

    data = readCSPrivilegeLevels(configFile);

    cipherID = getCipherID(auth, integrity, confidentiality);
    if (cipherID == "Invalid")
    {
        log<level::ERR>("Error in getting Cipher Suite ID");
        return PRIVILEGE_ERROR;
    }
    if (data == nullptr)
    {
        log<level::ERR>("Null value in data");
        return PRIVILEGE_ERROR;
    }
    try
    {
        priv = static_cast<uint8_t>(convertToPrivLimitIndex(
            static_cast<std::string>(data[channelNum][cipherID])));
    }
    catch (...)
    {
        log<level::ERR>("Error in static casting");
        return PRIVILEGE_ERROR;
    }
    return priv;
}

} // namespace ipmi
