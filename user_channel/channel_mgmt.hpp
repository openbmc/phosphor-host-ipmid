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

#include <boost/interprocess/sync/file_lock.hpp>
#include <boost/interprocess/sync/named_recursive_mutex.hpp>
#include <cstdint>
#include <ctime>
#include <nlohmann/json.hpp>
#include <sdbusplus/bus.hpp>

namespace ipmi
{

using Json = nlohmann::json;

using DbusVariant =
    sdbusplus::message::variant<std::vector<std::string>, std::string, bool>;

using DbusChObjProperties = std::vector<std::pair<std::string, DbusVariant>>;

static constexpr const char* ipmiChannelMutex = "ipmi_channel_mutex";
static constexpr const char* ipmiChMutexCleanupLockFile =
    "/var/lib/ipmi/ipmi_channel_mutex_cleanup";

struct ChannelAccessData
{
    ChannelAccess chNonVoltData;
    ChannelAccess chVoltData;
    bool callbackconn; // TODO: future use
};

struct ChannelData
{
    std::string chName;
    uint8_t chID;
    bool isChValid;
    uint8_t activeSessCount;
    ChannelInfo chInfo;
    ChannelAccessData chAccess;
};

class ChannelConfig;

ChannelConfig& getChannelConfigObject();

class ChannelConfig
{
  public:
    ChannelConfig(const ChannelConfig&) = delete;
    ChannelConfig& operator=(const ChannelConfig&) = delete;
    ChannelConfig(ChannelConfig&&) = delete;
    ChannelConfig& operator=(ChannelConfig&&) = delete;

    ~ChannelConfig();
    ChannelConfig();

    bool isValidChannel(const uint8_t& chNum);

    bool isValidAuthType(const uint8_t& chNum, const uint8_t& authType);

    EChannelSessSupported getChannelSessionSupport(const uint8_t& chNum);

    int getChannelActiveSessions(const uint8_t& chNum);

    ipmi_ret_t getChannelInfo(const uint8_t& chNum, ChannelInfo& chInfo);

    ipmi_ret_t getChannelAccessData(const uint8_t& chNum,
                                    ChannelAccess& chAccessData);

    ipmi_ret_t setChannelAccessData(const uint8_t& chNum,
                                    const ChannelAccess& chAccessData,
                                    const uint8_t& setFlag);

    ipmi_ret_t getChannelAccessPersistData(const uint8_t& chNum,
                                           ChannelAccess& chAccessData);

    ipmi_ret_t setChannelAccessPersistData(const uint8_t& chNum,
                                           const ChannelAccess& chAccessData,
                                           const uint8_t& setFlag);

    ipmi_ret_t getChannelAuthTypeSupported(const uint8_t& chNum,
                                           uint8_t& authTypeSupported);

    ipmi_ret_t getChannelEnabledAuthType(const uint8_t& chNum,
                                         const uint8_t& priv,
                                         uint8_t& authType);

    CommandPrivilege convertToPrivLimitIndex(const std::string& value);

    int writeChannelPersistData();

    int writeChannelVolatileData();

    ChannelData* getChannelDataPtr(const uint8_t& chNum);

    uint32_t signalFlag = 0;

    std::unique_ptr<boost::interprocess::named_recursive_mutex> channelMutex{
        nullptr};

  private:
    ChannelData channelData[maxIpmiChannels];
    std::time_t nvFileLastUpdatedTime;
    std::time_t voltFileLastUpdatedTime;
    std::time_t getUpdatedFileTime(const std::string& fileName);
    boost::interprocess::file_lock mutexCleanupLock;
    sdbusplus::bus::bus bus;
    bool signalHndlrObject = false;
    boost::interprocess::file_lock sigHndlrLock;

    void initChannelPersistData();

    void setDefaultChannelConfig(const uint8_t& chNum,
                                 const std::string& chName);

    int loadChannelConfig();

    int readChannelPersistData();

    int readChannelVolatileData();

    int checkAndReloadNVData();

    int checkAndReloadVoltData();

    int syncNetworkChannelConfig();

    int setDbusProperty(sdbusplus::bus::bus& bus, const std::string& service,
                        const std::string& objPath,
                        const std::string& interface,
                        const std::string& property, const DbusVariant& value);

    int getDbusProperty(sdbusplus::bus::bus& bus, const std::string& service,
                        const std::string& objPath,
                        const std::string& interface,
                        const std::string& property, DbusVariant& value);

    Json readJsonFile(const std::string& configFile);

    int writeJsonFile(const std::string& configFile, const Json& jsonData);

    EChannelAccessMode convertToAccessModeIndex(const std::string& mode);

    std::string convertToAccessModeString(const uint8_t& value);

    std::string convertToPrivLimitString(const uint8_t& value);

    EChannelSessSupported
        convertToSessionSupportIndex(const std::string& value);

    EChannelMediumType convertToMediumTypeIndex(const std::string& value);

    EChannelProtocolType convertToProtocolTypeIndex(const std::string& value);

    uint8_t convertToChannelIndexNumber(const uint8_t& chNum);

    std::string convertToNetInterface(const std::string& value);
};

} // namespace ipmi
