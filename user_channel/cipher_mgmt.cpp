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

#include <phosphor-logging/lg2.hpp>

#include <filesystem>
#include <fstream>

namespace ipmi
{

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
        lg2::error("CS privilege levels default file does not exist...");
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
        lg2::error("JSON file not found");
        return nullptr;
    }

    Json data = nullptr;
    try
    {
        data = Json::parse(jsonFile, nullptr, false);
    }
    catch (const Json::parse_error& e)
    {
        lg2::error(
            "Corrupted cipher suite privilege levels config file: {ERROR}",
            "ERROR", e);
    }

    return data;
}

int CipherConfig::writeCSPrivilegeLevels(const Json& jsonData)
{
    std::string tmpFile =
        static_cast<std::string>(cipherSuitePrivFileName) + "_tmpXXXXXX";

    std::vector<char> tmpRandomFile(tmpFile.length() + 1);
    strncpy(tmpRandomFile.data(), tmpFile.c_str(), tmpFile.length() + 1);

    int fd = mkstemp(tmpRandomFile.data());
    fchmod(fd, 0644);

    if (fd < 0)
    {
        lg2::error("Error opening CS privilege level config file: {FILE_NAME}",
                   "FILE_NAME", tmpFile);
        return -EIO;
    }
    const auto& writeData = jsonData.dump();
    if (write(fd, writeData.c_str(), writeData.size()) !=
        static_cast<ssize_t>(writeData.size()))
    {
        close(fd);
        lg2::error("Error writing CS privilege level config file: {FILE_NAME}",
                   "FILE_NAME", tmpFile);
        unlink(tmpRandomFile.data());
        return -EIO;
    }
    close(fd);

    if (std::rename(tmpRandomFile.data(), cipherSuitePrivFileName.c_str()))
    {
        lg2::error("Error renaming CS privilege level config file: {FILE_NAME}",
                   "FILE_NAME", tmpFile);
        unlink(tmpRandomFile.data());
        return -EIO;
    }

    return 0;
}

uint4_t CipherConfig::convertToPrivLimitIndex(const std::string& value)
{
    auto iter = std::find(ipmi::privList.begin(), ipmi::privList.end(), value);
    if (iter == privList.end())
    {
        lg2::error("Invalid privilege: {PRIV_STR}", "PRIV_STR", value);
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
        lg2::error("Invalid channel number: {CHANNEL}", "CHANNEL", chNum);
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
        lg2::error("Invalid channel number: {CHANNEL}", "CHANNEL", chNum);
        return ccInvalidFieldRequest;
    }

    Json jsonData;
    if (!fs::exists(cipherSuitePrivFileName))
    {
        lg2::info("CS privilege levels user settings file does not "
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
        lg2::error("Error in setting CS Privilege Levels.");
        return ccUnspecifiedError;
    }

    updateCSPrivilegesMap(jsonData);
    return ccSuccess;
}

} // namespace ipmi
