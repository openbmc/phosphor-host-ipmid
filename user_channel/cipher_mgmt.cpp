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
#include <phosphor-logging/log.hpp>

namespace ipmi
{

using namespace phosphor::logging;
namespace fs = std::filesystem;

CipherConfig& getCipherConfigObject(std::string csFileName)
{
    static CipherConfig cipherConfig(csFileName);
    return cipherConfig;
}

CipherConfig::CipherConfig(std::string csFileName)
{
    cipherSuitePrivFileName = csFileName;
    if (!fs::exists(cipherSuitePrivFileName))
    {
        log<level::INFO>(
            "CS privilege levels file does not exist. Initialising...");
        initCSPrivilegeLevelsPersistData();
    }
}

Json CipherConfig::readCSPrivilegeLevels()
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
        log<level::ERR>("Corrupted cipher suite privilege levels config file.",
                        entry("MSG: %s", e.what()));

        // TODO:Throw error which needs to be handled by the caller - Ex:
        // Get/Set Privilege Levels. Currently don't throw to allow ipmid to
        // continue
    }

    return data;
}

int CipherConfig::writeCSPrivilegeLevels(const Json& jsonData)
{
    const std::string tmpFile =
        static_cast<std::string>(cipherSuitePrivFileName) + "_tmp";

    int fd = open(tmpFile.c_str(), O_CREAT | O_WRONLY | O_TRUNC | O_SYNC,
                  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
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
        return -EIO;
    }
    close(fd);

    if (std::rename(tmpFile.c_str(), cipherSuitePrivFileName.c_str()) != 0)
    {
        log<level::ERR>("Error renaming CS privilege level config file",
                        entry("FILE_NAME=%s", tmpFile.c_str()));
        return -EIO;
    }

    return 0;
}

void CipherConfig::initCSPrivilegeLevelsPersistData()
{
    Json initData;

    for (uint8_t chNum = 0; chNum < ipmi::maxIpmiChannels; chNum++)
    {
        Json privData;

        std::string chKey = "Channel" + std::to_string(chNum);
        for (uint8_t csNum = 0; csNum < maxCSRecords; csNum++)
        {
            auto csKey = "CipherID" + std::to_string(csNum);
            // By default, provide Admin privileges for all Cipher Suites,
            // across all channels
            privData[csKey] = privAdmin;
        }
        initData[chKey] = privData;
    }

    if (writeCSPrivilegeLevels(initData) != 0)
    {
        log<level::ERR>("Error initialising CS Privilege Levels.");
    }

    log<level::DEBUG>("Initialised CS Privilege Levles");
    return;
}

} // namespace ipmi
