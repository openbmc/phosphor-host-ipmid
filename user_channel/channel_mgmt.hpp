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
#include <cstdint>
#include <ctime>
#include <boost/interprocess/sync/named_recursive_mutex.hpp>
#include <nlohmann/json.hpp>
#include "channelcommands.hpp"

namespace ipmi
{

using Json = nlohmann::json;

static constexpr const char *IPMI_CHANNEL_MUTEX = "ipmi_channel_mutex";

// TODO: This should be declared in ipmi-api.h
static constexpr uint8_t PRIVILEGE_MAX = PRIVILEGE_OEM + 1;

enum AccessSetFlag
{
    setAccessMode = (1 << 0),
    setUserAuthEnabled = (1 << 1),
    setMsgAuthEnabled = (1 << 2),
    setAlertingEnabled = (1 << 3),
    setPrivLimit = (1 << 4),
};

// Struct to store channel access data
struct ChannelAccess
{
    uint8_t accessMode;
    bool userAuthDisabled;
    bool perMsgAuthDisabled;
    bool alertingDisabled;
    uint8_t privLimit;
};

// Struct store channel info data
struct ChannelInfo
{
    uint8_t mediumType;
    uint8_t protocolType;
    uint8_t sessionSupported;
    bool isIpmi; // Is session IPMI
    // This is used in Get LAN Configuration parameter.
    // This holds the supported AuthTypes for a given channel.
    uint8_t authTypeSupported;
};

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

ChannelConfig &getChannelConfigObject();

class ChannelConfig
{
  public:
    ChannelConfig(const ChannelConfig &) = delete;
    ChannelConfig &operator=(const ChannelConfig &) = delete;
    ChannelConfig(ChannelConfig &&) = delete;
    ChannelConfig &operator=(ChannelConfig &&) = delete;

    ~ChannelConfig() = default;
    ChannelConfig();

    bool isValidChannel(const uint8_t &chNum);

    bool isDeviceExist(const uint8_t &chNum);

    bool isValidPrivLimit(const uint8_t &privLimit);

    bool isValidAccessMode(const uint8_t &accessMode);

    bool isValidAuthType(const uint8_t &chNum, const uint8_t &authType);

    EChannelSessSupported getChannelSessionSupport(const uint8_t &chNum);

    int getChannelActiveSessions(const uint8_t &chNum);

    ipmi_ret_t getChannelInfo(const uint8_t &chNum, ChannelInfo &chInfo);

    ipmi_ret_t getChannelAccessData(const uint8_t &chNum,
                                    ChannelAccess &chAccessData);

    ipmi_ret_t setChannelAccessData(const uint8_t &chNum,
                                    const ChannelAccess &chAccessData,
                                    const uint8_t &setFlag);

    ipmi_ret_t getChannelAccessPersistData(const uint8_t &chNum,
                                           ChannelAccess &chAccessData);

    ipmi_ret_t setChannelAccessPersistData(const uint8_t &chNum,
                                           const ChannelAccess &chAccessData,
                                           const uint8_t &setFlag);

    ipmi_ret_t getChannelAuthTypeSupported(const uint8_t &chNum,
                                           uint8_t &authTypeSupported);

    ipmi_ret_t getChannelEnabledAuthType(const uint8_t &chNum,
                                         const uint8_t &priv,
                                         uint8_t &authType);

  private:
    ChannelData channelData[maxIpmiChannels];
    std::time_t nvFileLastUpdatedTime;
    std::time_t voltFileLastUpdatedTime;
    std::time_t getUpdatedFileTime(const std::string &fileName);
    boost::interprocess::named_recursive_mutex channelMutex{
        boost::interprocess::open_or_create, IPMI_CHANNEL_MUTEX};

    void initChannelPersistData();

    void setDefaultChannelConfig(const uint8_t &chNum,
                                 const std::string &chName);

    int loadChannelConfig();

    int readChannelPersistData();

    int writeChannelPersistData();

    int readChannelVolatileData();

    int writeChannelVolatileData();

    int checkAndReloadNVData();

    int checkAndReloadVoltData();

    Json readJsonFile(const std::string &configFile);

    int writeJsonFile(const std::string &configFile, const Json &jsonData);

    EChannelAccessMode convertToAccessModeIndex(const std::string &mode);

    std::string convertToAccessModeString(const uint8_t &value);

    CommandPrivilege convertToPrivLimitIndex(const std::string &value);

    std::string convertToPrivLimitString(const uint8_t &value);

    EChannelSessSupported
        convertToSessionSupportIndex(const std::string &value);

    EChannelMediumType convertToMediumTypeIndex(const std::string &value);

    EChannelProtocolType convertToProtocolTypeIndex(const std::string &value);
};

} // namespace ipmi
