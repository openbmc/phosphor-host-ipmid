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

#include "channel_mgmt.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <boost/assign.hpp>
#include <boost/bimap.hpp>
#include <boost/interprocess/sync/scoped_lock.hpp>
#include <exception>
#include <experimental/filesystem>
#include <fstream>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/server/object.hpp>
#include <unordered_map>

#include "apphandler.h"

namespace ipmi
{

using namespace phosphor::logging;

static constexpr const char* channelAccessDefaultFilename =
    "/usr/share/ipmi-providers/channel_access.json";
static constexpr const char* channelConfigDefaultFilename =
    "/usr/share/ipmi-providers/channel_config.json";
static constexpr const char* channelNvDataFilename =
    "/var/lib/ipmi/channel_access_nv.json";
static constexpr const char* channelVolatileDataFilename =
    "/run/ipmi/channel_access_volatile.json";

// TODO: Get the service name dynamically..
static constexpr const char* networkIntfServiceName =
    "xyz.openbmc_project.Network";
static constexpr const char* networkIntfObjectBasePath =
    "/xyz/openbmc_project/network";
static constexpr const char* networkChConfigIntfName =
    "xyz.openbmc_project.Channel.ChannelAccess";
static constexpr const char* privilegePropertyString = "MaxPrivilege";
static constexpr const char* dBusPropertiesInterface =
    "org.freedesktop.DBus.Properties";
static constexpr const char* propertiesChangedSignal = "PropertiesChanged";

// STRING DEFINES: Should sync with key's in JSON
static constexpr const char* nameString = "name";
static constexpr const char* isValidString = "is_valid";
static constexpr const char* activeSessionsString = "active_sessions";
static constexpr const char* channelInfoString = "channel_info";
static constexpr const char* mediumTypeString = "medium_type";
static constexpr const char* protocolTypeString = "protocol_type";
static constexpr const char* sessionSupportedString = "session_supported";
static constexpr const char* isIpmiString = "is_ipmi";
static constexpr const char* authTypeSupportedString = "auth_type_supported";
static constexpr const char* accessModeString = "access_mode";
static constexpr const char* userAuthDisabledString = "user_auth_disabled";
static constexpr const char* perMsgAuthDisabledString = "per_msg_auth_disabled";
static constexpr const char* alertingDisabledString = "alerting_disabled";
static constexpr const char* privLimitString = "priv_limit";
static constexpr const char* authTypeEnabledString = "auth_type_enabled";

// Default values
static constexpr const char* defaultChannelName = "RESERVED";
static constexpr const uint8_t defaultMediumType =
    static_cast<uint8_t>(EChannelMediumType::reserved);
static constexpr const uint8_t defaultProtocolType =
    static_cast<uint8_t>(EChannelProtocolType::reserved);
static constexpr const uint8_t defaultSessionSupported =
    static_cast<uint8_t>(EChannelSessSupported::none);
static constexpr const uint8_t defaultAuthType =
    static_cast<uint8_t>(EAuthType::none);
static constexpr const bool defaultIsIpmiState = false;

std::unique_ptr<sdbusplus::bus::match_t> chPropertiesSignal(nullptr);

// String mappings use in JSON config file
static std::unordered_map<std::string, EChannelMediumType> mediumTypeMap = {
    {"reserved", EChannelMediumType::reserved},
    {"ipmb", EChannelMediumType::ipmb},
    {"icmb-v1.0", EChannelMediumType::icmbV10},
    {"icmb-v0.9", EChannelMediumType::icmbV09},
    {"lan-802.3", EChannelMediumType::lan8032},
    {"serial", EChannelMediumType::serial},
    {"other-lan", EChannelMediumType::otherLan},
    {"pci-smbus", EChannelMediumType::pciSmbus},
    {"smbus-v1.0", EChannelMediumType::smbusV11},
    {"smbus-v2.0", EChannelMediumType::smbusV20},
    {"usb-1x", EChannelMediumType::usbV1x},
    {"usb-2x", EChannelMediumType::usbV2x},
    {"system-interface", EChannelMediumType::systemInterface},
    {"oem", EChannelMediumType::oem},
    {"unknown", EChannelMediumType::unknown}};

static std::unordered_map<std::string, EChannelProtocolType> protocolTypeMap = {
    {"na", EChannelProtocolType::na},
    {"ipmb-1.0", EChannelProtocolType::ipmbV10},
    {"icmb-2.0", EChannelProtocolType::icmbV11},
    {"reserved", EChannelProtocolType::reserved},
    {"ipmi-smbus", EChannelProtocolType::ipmiSmbus},
    {"kcs", EChannelProtocolType::kcs},
    {"smic", EChannelProtocolType::smic},
    {"bt-10", EChannelProtocolType::bt10},
    {"bt-15", EChannelProtocolType::bt15},
    {"tmode", EChannelProtocolType::tMode},
    {"oem", EChannelProtocolType::oem}};

static std::array<std::string, 4> accessModeList = {
    "disabled", "pre-boot", "always_available", "shared"};

static std::array<std::string, 4> sessionSupportList = {
    "session-less", "single-session", "multi-session", "session-based"};

static std::array<std::string, PRIVILEGE_OEM + 1> privList = {
    "priv-reserved", "priv-callback", "priv-user",
    "priv-operator", "priv-admin",    "priv-oem"};

using bimapType = boost::bimap<std::string, std::string>;
bimapType channelNameIntfMap = boost::assign::list_of<bimapType::relation>(
    "LAN1", "eth0")("LAN2", "eth1")("LAN3", "eth2");

std::string convertToChannelName(const std::string& intfName)
{
    bimapType::right_map::const_iterator it =
        channelNameIntfMap.right.find(intfName);
    if (it == channelNameIntfMap.right.end())
    {
        log<level::ERR>("Invalid network interface.",
                        entry("INTF:%s", intfName.c_str()));
        throw std::invalid_argument("Invalid network interface");
    }

    return it->second;
}

std::string getNetIntfFromPath(const std::string& path)
{
    std::size_t pos = path.find(networkIntfObjectBasePath);
    if (pos == std::string::npos)
    {
        log<level::ERR>("Invalid interface path.",
                        entry("PATH:%s", path.c_str()));
        throw std::invalid_argument("Invalid interface path");
    }
    std::string intfName =
        path.substr(pos + strlen(networkIntfObjectBasePath) + 1);
    return intfName;
}

void processChAccessPropChange(ChannelConfig& chConfig, const std::string& path,
                               const DbusChObjProperties& chProperties)
{
    // Get interface name from path. ex: '/xyz/openbmc_project/network/eth0'
    std::string intfName;
    try
    {
        intfName = getNetIntfFromPath(path);
    }
    catch (const std::invalid_argument& e)
    {
        log<level::ERR>("Exception: ", entry("MSG: %s", e.what()));
        return;
    }

    // Get the property name and value
    std::string intfPrivStr;
    std::string propName;
    for (const auto& prop : chProperties)
    {
        if (prop.first == privilegePropertyString)
        {
            propName = privilegePropertyString;
            intfPrivStr = prop.second.get<std::string>();
            break;
        }
    }

    if (propName == privilegePropertyString)
    {
        if (intfPrivStr.empty())
        {
            log<level::ERR>("Invalid privilege string.",
                            entry("INTF:%s", intfName.c_str()));
            return;
        }
        uint8_t intfPriv = 0;
        std::string channelName;
        try
        {
            intfPriv = static_cast<uint8_t>(
                chConfig.convertToPrivLimitIndex(intfPrivStr));
            channelName = convertToChannelName(intfName);
        }
        catch (const std::invalid_argument& e)
        {
            log<level::ERR>("Exception: ", entry("MSG: %s", e.what()));
            return;
        }

        boost::interprocess::scoped_lock<
            boost::interprocess::named_recursive_mutex>
            channelLock{*chConfig.channelMutex};
        uint8_t chNum = 0;
        ChannelData* chData;
        for (chNum = 0; chNum < maxIpmiChannels; chNum++)
        {
            chData = chConfig.getChannelDataPtr(chNum);
            if (chData->chName == channelName)
            {
                break;
            }
        }
        if (chNum >= maxIpmiChannels)
        {
            log<level::ERR>("Invalid interface in signal path");
            return;
        }

        if (chConfig.signalFlag & (1 << chNum))
        {
            chConfig.signalFlag &= ~(1 << chNum);
            log<level::DEBUG>(
                "Request originated from IPMI so ignoring signal");
            return;
        }

        if (chData->chAccess.chNonVoltData.privLimit != intfPriv)
        {
            // Update NV data
            chData->chAccess.chNonVoltData.privLimit = intfPriv;
            if (chConfig.writeChannelPersistData() != 0)
            {
                log<level::ERR>("Failed to update the persist data file");
                return;
            }

            // Update Volatile data
            if (chData->chAccess.chVoltData.privLimit != intfPriv)
            {
                chData->chAccess.chVoltData.privLimit = intfPriv;
                if (chConfig.writeChannelVolatileData() != 0)
                {
                    log<level::ERR>("Failed to update the volatile data file");
                    return;
                }
            }
        }
    }
    else
    {
        log<level::ERR>("Unknown signal caught.");
    }
    return;
}

ChannelConfig& getChannelConfigObject()
{
    static ChannelConfig channelConfig;
    return channelConfig;
}

ChannelConfig::~ChannelConfig()
{
    if (signalHndlrObject == true)
    {
        chPropertiesSignal.reset();
        sigHndlrLock.unlock();
    }
}

ChannelConfig::ChannelConfig() : bus(ipmid_get_sd_bus_connection())
{
    std::ofstream mutexCleanUpFile;
    mutexCleanUpFile.open(ipmiChMutexCleanupLockFile,
                          std::ofstream::out | std::ofstream::app);
    if (!mutexCleanUpFile.good())
    {
        log<level::DEBUG>("Unable to open mutex cleanup file");
        return;
    }
    mutexCleanUpFile.close();
    mutexCleanupLock =
        boost::interprocess::file_lock(ipmiChMutexCleanupLockFile);
    if (mutexCleanupLock.try_lock())
    {
        boost::interprocess::named_recursive_mutex::remove(ipmiChannelMutex);
        channelMutex =
            std::make_unique<boost::interprocess::named_recursive_mutex>(
                boost::interprocess::open_or_create, ipmiChannelMutex);
        mutexCleanupLock.lock_sharable();
    }
    else
    {
        mutexCleanupLock.lock_sharable();
        channelMutex =
            std::make_unique<boost::interprocess::named_recursive_mutex>(
                boost::interprocess::open_or_create, ipmiChannelMutex);
    }

    initChannelPersistData();

    sigHndlrLock = boost::interprocess::file_lock(channelNvDataFilename);
    // Register it for single object and single process either netipimd /
    // host-ipmid
    if (chPropertiesSignal == nullptr && sigHndlrLock.try_lock())
    {
        log<level::DEBUG>("Registering channel signal handler.");
        chPropertiesSignal = std::make_unique<sdbusplus::bus::match_t>(
            bus,
            sdbusplus::bus::match::rules::path_namespace(
                networkIntfObjectBasePath) +
                sdbusplus::bus::match::rules::type::signal() +
                sdbusplus::bus::match::rules::member(propertiesChangedSignal) +
                sdbusplus::bus::match::rules::interface(
                    dBusPropertiesInterface) +
                sdbusplus::bus::match::rules::argN(0, networkChConfigIntfName),
            [&](sdbusplus::message::message& msg) {
                DbusChObjProperties props;
                std::string iface;
                std::string path = msg.get_path();
                msg.read(iface, props);
                processChAccessPropChange(*this, path, props);
            });
        signalHndlrObject = true;
    }
}

ChannelData* ChannelConfig::getChannelDataPtr(const uint8_t& chNum)
{
    // reload data before using it.
    checkAndReloadVoltData();
    return &channelData[chNum];
}

bool ChannelConfig::isValidChannel(const uint8_t& chNum)
{
    if (chNum > maxIpmiChannels)
    {
        log<level::DEBUG>("Invalid channel ID - Out of range");
        return false;
    }

    if (channelData[chNum].isChValid == false)
    {
        log<level::DEBUG>("Channel is not valid");
        return false;
    }

    return true;
}

EChannelSessSupported
    ChannelConfig::getChannelSessionSupport(const uint8_t& chNum)
{
    EChannelSessSupported chSessSupport =
        (EChannelSessSupported)channelData[chNum].chInfo.sessionSupported;
    return chSessSupport;
}

bool ChannelConfig::isValidAuthType(const uint8_t& chNum,
                                    const uint8_t& authType)
{
    if ((authType < static_cast<uint8_t>(EAuthType::md2)) ||
        (authType > static_cast<uint8_t>(EAuthType::oem)))
    {
        log<level::DEBUG>("Invalid authentication type");
        return false;
    }

    uint8_t authTypeSupported = channelData[chNum].chInfo.authTypeSupported;
    if (!(authTypeSupported & (1 << authType)))
    {
        log<level::DEBUG>("Authentication type is not supported.");
        return false;
    }

    return true;
}

int ChannelConfig::getChannelActiveSessions(const uint8_t& chNum)
{
    // TODO: TEMPORARY FIX
    // Channels active session count is managed separatly
    // by monitoring channel session which includes LAN and
    // RAKP layer changes. This will be updated, once the
    // authentication part is implimented.
    return channelData[chNum].activeSessCount;
}

ipmi_ret_t ChannelConfig::getChannelInfo(const uint8_t& chNum,
                                         ChannelInfo& chInfo)
{
    if (!isValidChannel(chNum))
    {
        log<level::DEBUG>("Invalid channel");
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    std::copy_n(reinterpret_cast<uint8_t*>(&channelData[chNum].chInfo),
                sizeof(channelData[chNum].chInfo),
                reinterpret_cast<uint8_t*>(&chInfo));

    return IPMI_CC_OK;
}

ipmi_ret_t ChannelConfig::getChannelAccessData(const uint8_t& chNum,
                                               ChannelAccess& chAccessData)
{
    if (!isValidChannel(chNum))
    {
        log<level::DEBUG>("Invalid channel");
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    if (getChannelSessionSupport(chNum) == EChannelSessSupported::none)
    {
        log<level::DEBUG>("Session-less channel doesn't have access data.");
        return IPMI_CC_ACTION_NOT_SUPPORTED_FOR_CHANNEL;
    }

    if (checkAndReloadVoltData() != 0)
    {
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    std::copy_n(
        reinterpret_cast<uint8_t*>(&channelData[chNum].chAccess.chVoltData),
        sizeof(channelData[chNum].chAccess.chVoltData),
        reinterpret_cast<uint8_t*>(&chAccessData));

    return IPMI_CC_OK;
}

ipmi_ret_t
    ChannelConfig::setChannelAccessData(const uint8_t& chNum,
                                        const ChannelAccess& chAccessData,
                                        const uint8_t& setFlag)
{
    if (!isValidChannel(chNum))
    {
        log<level::DEBUG>("Invalid channel");
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    if (getChannelSessionSupport(chNum) == EChannelSessSupported::none)
    {
        log<level::DEBUG>("Session-less channel doesn't have access data.");
        return IPMI_CC_ACTION_NOT_SUPPORTED_FOR_CHANNEL;
    }

    if ((setFlag & setAccessMode) &&
        (!isValidAccessMode(chAccessData.accessMode)))
    {
        log<level::DEBUG>("Invalid access mode specified");
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        channelLock{*channelMutex};

    if (checkAndReloadVoltData() != 0)
    {
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    if (setFlag & setAccessMode)
    {
        channelData[chNum].chAccess.chVoltData.accessMode =
            chAccessData.accessMode;
    }
    if (setFlag & setUserAuthEnabled)
    {
        channelData[chNum].chAccess.chVoltData.userAuthDisabled =
            chAccessData.userAuthDisabled;
    }
    if (setFlag & setMsgAuthEnabled)
    {
        channelData[chNum].chAccess.chVoltData.perMsgAuthDisabled =
            chAccessData.perMsgAuthDisabled;
    }
    if (setFlag & setAlertingEnabled)
    {
        channelData[chNum].chAccess.chVoltData.alertingDisabled =
            chAccessData.alertingDisabled;
    }
    if (setFlag & setPrivLimit)
    {
        channelData[chNum].chAccess.chVoltData.privLimit =
            chAccessData.privLimit;
    }

    // Write Volatile data to file
    if (writeChannelVolatileData() != 0)
    {
        log<level::DEBUG>("Failed to update the channel volatile data");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    return IPMI_CC_OK;
}

ipmi_ret_t
    ChannelConfig::getChannelAccessPersistData(const uint8_t& chNum,
                                               ChannelAccess& chAccessData)
{
    if (!isValidChannel(chNum))
    {
        log<level::DEBUG>("Invalid channel");
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    if (getChannelSessionSupport(chNum) == EChannelSessSupported::none)
    {
        log<level::DEBUG>("Session-less channel doesn't have access data.");
        return IPMI_CC_ACTION_NOT_SUPPORTED_FOR_CHANNEL;
    }

    if (checkAndReloadNVData() != 0)
    {
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    std::copy_n(
        reinterpret_cast<uint8_t*>(&channelData[chNum].chAccess.chNonVoltData),
        sizeof(channelData[chNum].chAccess.chNonVoltData),
        reinterpret_cast<uint8_t*>(&chAccessData));

    return IPMI_CC_OK;
}

ipmi_ret_t ChannelConfig::setChannelAccessPersistData(
    const uint8_t& chNum, const ChannelAccess& chAccessData,
    const uint8_t& setFlag)
{
    if (!isValidChannel(chNum))
    {
        log<level::DEBUG>("Invalid channel");
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    if (getChannelSessionSupport(chNum) == EChannelSessSupported::none)
    {
        log<level::DEBUG>("Session-less channel doesn't have access data.");
        return IPMI_CC_ACTION_NOT_SUPPORTED_FOR_CHANNEL;
    }

    if ((setFlag & setAccessMode) &&
        (!isValidAccessMode(chAccessData.accessMode)))
    {
        log<level::DEBUG>("Invalid access mode specified");
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        channelLock{*channelMutex};

    if (checkAndReloadNVData() != 0)
    {
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    if (setFlag & setAccessMode)
    {
        channelData[chNum].chAccess.chNonVoltData.accessMode =
            chAccessData.accessMode;
    }
    if (setFlag & setUserAuthEnabled)
    {
        channelData[chNum].chAccess.chNonVoltData.userAuthDisabled =
            chAccessData.userAuthDisabled;
    }
    if (setFlag & setMsgAuthEnabled)
    {
        channelData[chNum].chAccess.chNonVoltData.perMsgAuthDisabled =
            chAccessData.perMsgAuthDisabled;
    }
    if (setFlag & setAlertingEnabled)
    {
        channelData[chNum].chAccess.chNonVoltData.alertingDisabled =
            chAccessData.alertingDisabled;
    }
    if (setFlag & setPrivLimit)
    {
        // Send Update to network channel config interfaces over dbus
        std::string intfName = convertToNetInterface(channelData[chNum].chName);
        std::string privStr = convertToPrivLimitString(chAccessData.privLimit);
        std::string networkIntfObj =
            std::string(networkIntfObjectBasePath) + "/" + intfName;
        try
        {
            if (0 != setDbusProperty(bus, networkIntfServiceName,
                                     networkIntfObj, networkChConfigIntfName,
                                     privilegePropertyString, privStr))
            {
                log<level::DEBUG>("Network interface does not exist",
                                  entry("INTERFACE:%s", intfName.c_str()));
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
        }
        catch (const sdbusplus::exception::SdBusError& e)
        {
            log<level::ERR>("Exception: Network interface does not exist");
            return IPMI_CC_INVALID_FIELD_REQUEST;
        }
        signalFlag |= (1 << chNum);
        channelData[chNum].chAccess.chNonVoltData.privLimit =
            chAccessData.privLimit;
    }

    // Write persistant data to file
    if (writeChannelPersistData() != 0)
    {
        log<level::DEBUG>("Failed to update the presist data file");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    return IPMI_CC_OK;
}

ipmi_ret_t
    ChannelConfig::getChannelAuthTypeSupported(const uint8_t& chNum,
                                               uint8_t& authTypeSupported)
{
    if (!isValidChannel(chNum))
    {
        log<level::DEBUG>("Invalid channel");
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    authTypeSupported = channelData[chNum].chInfo.authTypeSupported;
    return IPMI_CC_OK;
}

ipmi_ret_t ChannelConfig::getChannelEnabledAuthType(const uint8_t& chNum,
                                                    const uint8_t& priv,
                                                    uint8_t& authType)
{
    if (!isValidChannel(chNum))
    {
        log<level::DEBUG>("Invalid channel");
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    if (getChannelSessionSupport(chNum) == EChannelSessSupported::none)
    {
        log<level::DEBUG>("Sessionless channel doesn't have access data.");
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    if (!isValidPrivLimit(priv))
    {
        log<level::DEBUG>("Invalid privilege specified.");
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    // TODO: Hardcoded for now. Need to implement.
    authType = static_cast<uint8_t>(EAuthType::none);

    return IPMI_CC_OK;
}

std::time_t ChannelConfig::getUpdatedFileTime(const std::string& fileName)
{
    struct stat fileStat;
    if (stat(fileName.c_str(), &fileStat) != 0)
    {
        log<level::DEBUG>("Error in getting last updated time stamp");
        return -1;
    }
    return fileStat.st_mtime;
}

EChannelAccessMode
    ChannelConfig::convertToAccessModeIndex(const std::string& mode)
{
    auto iter = std::find(accessModeList.begin(), accessModeList.end(), mode);
    if (iter == accessModeList.end())
    {
        log<level::ERR>("Invalid access mode.",
                        entry("MODE_STR=%s", mode.c_str()));
        throw std::invalid_argument("Invalid access mode.");
    }

    return static_cast<EChannelAccessMode>(
        std::distance(accessModeList.begin(), iter));
}

std::string ChannelConfig::convertToAccessModeString(const uint8_t& value)
{
    if (accessModeList.size() <= value)
    {
        log<level::ERR>("Invalid access mode.", entry("MODE_IDX=%d", value));
        throw std::invalid_argument("Invalid access mode.");
    }

    return accessModeList.at(value);
}

CommandPrivilege
    ChannelConfig::convertToPrivLimitIndex(const std::string& value)
{
    auto iter = std::find(privList.begin(), privList.end(), value);
    if (iter == privList.end())
    {
        log<level::ERR>("Invalid privilege.",
                        entry("PRIV_STR=%s", value.c_str()));
        throw std::invalid_argument("Invalid privilege.");
    }

    return static_cast<CommandPrivilege>(std::distance(privList.begin(), iter));
}

std::string ChannelConfig::convertToPrivLimitString(const uint8_t& value)
{
    if (privList.size() <= value)
    {
        log<level::ERR>("Invalid privilege.", entry("PRIV_IDX=%d", value));
        throw std::invalid_argument("Invalid privilege.");
    }

    return privList.at(value);
}

EChannelSessSupported
    ChannelConfig::convertToSessionSupportIndex(const std::string& value)
{
    auto iter =
        std::find(sessionSupportList.begin(), sessionSupportList.end(), value);
    if (iter == sessionSupportList.end())
    {
        log<level::ERR>("Invalid session supported.",
                        entry("SESS_STR=%s", value.c_str()));
        throw std::invalid_argument("Invalid session supported.");
    }

    return static_cast<EChannelSessSupported>(
        std::distance(sessionSupportList.begin(), iter));
}

EChannelMediumType
    ChannelConfig::convertToMediumTypeIndex(const std::string& value)
{
    std::unordered_map<std::string, EChannelMediumType>::iterator it =
        mediumTypeMap.find(value);
    if (it == mediumTypeMap.end())
    {
        log<level::ERR>("Invalid medium type.",
                        entry("MEDIUM_STR=%s", value.c_str()));
        throw std::invalid_argument("Invalid medium type.");
    }

    return static_cast<EChannelMediumType>(it->second);
}

EChannelProtocolType
    ChannelConfig::convertToProtocolTypeIndex(const std::string& value)
{
    std::unordered_map<std::string, EChannelProtocolType>::iterator it =
        protocolTypeMap.find(value);
    if (it == protocolTypeMap.end())
    {
        log<level::ERR>("Invalid protocol type.",
                        entry("PROTO_STR=%s", value.c_str()));
        throw std::invalid_argument("Invalid protocol type.");
    }

    return static_cast<EChannelProtocolType>(it->second);
}

Json ChannelConfig::readJsonFile(const std::string& configFile)
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

int ChannelConfig::writeJsonFile(const std::string& configFile,
                                 const Json& jsonData)
{
    std::ofstream jsonFile(configFile);
    if (!jsonFile.good())
    {
        log<level::ERR>("JSON file not found");
        return -1;
    }

    // Write JSON to file
    jsonFile << jsonData;

    jsonFile.flush();
    return 0;
}

void ChannelConfig::setDefaultChannelConfig(const uint8_t& chNum,
                                            const std::string& chName)
{
    channelData[chNum].chName = chName;
    channelData[chNum].chID = chNum;
    channelData[chNum].isChValid = false;
    channelData[chNum].activeSessCount = 0;

    channelData[chNum].chInfo.mediumType = defaultMediumType;
    channelData[chNum].chInfo.protocolType = defaultProtocolType;
    channelData[chNum].chInfo.sessionSupported = defaultSessionSupported;
    channelData[chNum].chInfo.isIpmi = defaultIsIpmiState;
    channelData[chNum].chInfo.authTypeSupported = defaultAuthType;
}

int ChannelConfig::loadChannelConfig()
{
    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        channelLock{*channelMutex};

    Json data = readJsonFile(channelConfigDefaultFilename);
    if (data == nullptr)
    {
        log<level::DEBUG>("Error in opening IPMI Channel data file");
        return -1;
    }

    try
    {
        // Fill in global structure
        for (uint8_t chNum = 0; chNum < maxIpmiChannels; chNum++)
        {
            std::fill(reinterpret_cast<uint8_t*>(&channelData[chNum]),
                      reinterpret_cast<uint8_t*>(&channelData[chNum]) +
                          sizeof(ChannelData),
                      0);
            std::string chKey = std::to_string(chNum);
            Json jsonChData = data[chKey].get<Json>();
            if (jsonChData.is_null())
            {
                log<level::WARNING>(
                    "Channel not configured so loading default.",
                    entry("CHANNEL_NUM:%d", chNum));
                // If user didn't want to configure specific channel (say
                // reserved channel), then load that index with default values.
                std::string chName(defaultChannelName);
                setDefaultChannelConfig(chNum, chName);
            }
            else
            {
                std::string chName = jsonChData[nameString].get<std::string>();
                channelData[chNum].chName = chName;
                channelData[chNum].chID = chNum;
                channelData[chNum].isChValid =
                    jsonChData[isValidString].get<bool>();
                channelData[chNum].activeSessCount =
                    jsonChData.value(activeSessionsString, 0);
                Json jsonChInfo = jsonChData[channelInfoString].get<Json>();
                if (jsonChInfo.is_null())
                {
                    log<level::ERR>("Invalid/corrupted channel config file");
                    return -1;
                }
                else
                {
                    std::string medTypeStr =
                        jsonChInfo[mediumTypeString].get<std::string>();
                    channelData[chNum].chInfo.mediumType = static_cast<uint8_t>(
                        convertToMediumTypeIndex(medTypeStr));
                    std::string protoTypeStr =
                        jsonChInfo[protocolTypeString].get<std::string>();
                    channelData[chNum].chInfo.protocolType =
                        static_cast<uint8_t>(
                            convertToProtocolTypeIndex(protoTypeStr));
                    std::string sessStr =
                        jsonChInfo[sessionSupportedString].get<std::string>();
                    channelData[chNum].chInfo.sessionSupported =
                        static_cast<uint8_t>(
                            convertToSessionSupportIndex(sessStr));
                    channelData[chNum].chInfo.isIpmi =
                        jsonChInfo[isIpmiString].get<bool>();
                    channelData[chNum].chInfo.authTypeSupported =
                        defaultAuthType;
                }
            }
        }
    }
    catch (const Json::exception& e)
    {
        log<level::DEBUG>("Json Exception caught.", entry("MSG:%s", e.what()));
        return -1;
    }
    catch (const std::invalid_argument& e)
    {
        log<level::ERR>("Corrupted config.", entry("MSG:%s", e.what()));
        return -1;
    }

    return 0;
}

int ChannelConfig::readChannelVolatileData()
{
    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        channelLock{*channelMutex};

    Json data = readJsonFile(channelVolatileDataFilename);
    if (data == nullptr)
    {
        log<level::DEBUG>("Error in opening IPMI Channel data file");
        return -1;
    }

    try
    {
        // Fill in global structure
        for (auto it = data.begin(); it != data.end(); ++it)
        {
            std::string chKey = it.key();
            uint8_t chNum = std::stoi(chKey, nullptr, 10);
            if ((chNum < 0) || (chNum > maxIpmiChannels))
            {
                log<level::DEBUG>(
                    "Invalid channel access entry in config file");
                throw std::out_of_range("Out of range - channel number");
            }
            Json jsonChData = it.value();
            if (!jsonChData.is_null())
            {
                std::string accModeStr =
                    jsonChData[accessModeString].get<std::string>();
                channelData[chNum].chAccess.chVoltData.accessMode =
                    static_cast<uint8_t>(convertToAccessModeIndex(accModeStr));
                channelData[chNum].chAccess.chVoltData.userAuthDisabled =
                    jsonChData[userAuthDisabledString].get<bool>();
                channelData[chNum].chAccess.chVoltData.perMsgAuthDisabled =
                    jsonChData[perMsgAuthDisabledString].get<bool>();
                channelData[chNum].chAccess.chVoltData.alertingDisabled =
                    jsonChData[alertingDisabledString].get<bool>();
                std::string privStr =
                    jsonChData[privLimitString].get<std::string>();
                channelData[chNum].chAccess.chVoltData.privLimit =
                    static_cast<uint8_t>(convertToPrivLimitIndex(privStr));
            }
            else
            {
                log<level::ERR>(
                    "Invalid/corrupted volatile channel access file",
                    entry("FILE: %s", channelVolatileDataFilename));
                throw std::runtime_error(
                    "Corrupted volatile channel access file");
            }
        }
    }
    catch (const Json::exception& e)
    {
        log<level::DEBUG>("Json Exception caught.", entry("MSG:%s", e.what()));
        throw std::runtime_error("Corrupted volatile channel access file");
    }
    catch (const std::invalid_argument& e)
    {
        log<level::ERR>("Corrupted config.", entry("MSG:%s", e.what()));
        throw std::runtime_error("Corrupted volatile channel access file");
    }

    // Update the timestamp
    voltFileLastUpdatedTime = getUpdatedFileTime(channelVolatileDataFilename);
    return 0;
}

int ChannelConfig::readChannelPersistData()
{
    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        channelLock{*channelMutex};

    Json data = readJsonFile(channelNvDataFilename);
    if (data == nullptr)
    {
        log<level::DEBUG>("Error in opening IPMI Channel data file");
        return -1;
    }

    try
    {
        // Fill in global structure
        for (auto it = data.begin(); it != data.end(); ++it)
        {
            std::string chKey = it.key();
            uint8_t chNum = std::stoi(chKey, nullptr, 10);
            if ((chNum < 0) || (chNum > maxIpmiChannels))
            {
                log<level::DEBUG>(
                    "Invalid channel access entry in config file");
                throw std::out_of_range("Out of range - channel number");
            }
            Json jsonChData = it.value();
            if (!jsonChData.is_null())
            {
                std::string accModeStr =
                    jsonChData[accessModeString].get<std::string>();
                channelData[chNum].chAccess.chNonVoltData.accessMode =
                    static_cast<uint8_t>(convertToAccessModeIndex(accModeStr));
                channelData[chNum].chAccess.chNonVoltData.userAuthDisabled =
                    jsonChData[userAuthDisabledString].get<bool>();
                channelData[chNum].chAccess.chNonVoltData.perMsgAuthDisabled =
                    jsonChData[perMsgAuthDisabledString].get<bool>();
                channelData[chNum].chAccess.chNonVoltData.alertingDisabled =
                    jsonChData[alertingDisabledString].get<bool>();
                std::string privStr =
                    jsonChData[privLimitString].get<std::string>();
                channelData[chNum].chAccess.chNonVoltData.privLimit =
                    static_cast<uint8_t>(convertToPrivLimitIndex(privStr));
            }
            else
            {
                log<level::ERR>("Invalid/corrupted nv channel access file",
                                entry("FILE:%s", channelNvDataFilename));
                throw std::runtime_error("Corrupted nv channel access file");
            }
        }
    }
    catch (const Json::exception& e)
    {
        log<level::DEBUG>("Json Exception caught.", entry("MSG:%s", e.what()));
        throw std::runtime_error("Corrupted nv channel access file");
    }
    catch (const std::invalid_argument& e)
    {
        log<level::ERR>("Corrupted config.", entry("MSG: %s", e.what()));
        throw std::runtime_error("Corrupted nv channel access file");
    }

    // Update the timestamp
    nvFileLastUpdatedTime = getUpdatedFileTime(channelNvDataFilename);
    return 0;
}

int ChannelConfig::writeChannelVolatileData()
{
    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        channelLock{*channelMutex};
    Json outData;

    try
    {
        for (uint8_t chNum = 0; chNum < maxIpmiChannels; chNum++)
        {
            if (getChannelSessionSupport(chNum) != EChannelSessSupported::none)
            {
                Json jsonObj;
                std::string chKey = std::to_string(chNum);
                std::string accModeStr = convertToAccessModeString(
                    channelData[chNum].chAccess.chVoltData.accessMode);
                jsonObj[accessModeString] = accModeStr;
                jsonObj[userAuthDisabledString] =
                    channelData[chNum].chAccess.chVoltData.userAuthDisabled;
                jsonObj[perMsgAuthDisabledString] =
                    channelData[chNum].chAccess.chVoltData.perMsgAuthDisabled;
                jsonObj[alertingDisabledString] =
                    channelData[chNum].chAccess.chVoltData.alertingDisabled;
                std::string privStr = convertToPrivLimitString(
                    channelData[chNum].chAccess.chVoltData.privLimit);
                jsonObj[privLimitString] = privStr;

                outData[chKey] = jsonObj;
            }
        }
    }
    catch (const std::invalid_argument& e)
    {
        log<level::ERR>("Corrupted config.", entry("MSG: %s", e.what()));
        return -1;
    }

    if (writeJsonFile(channelVolatileDataFilename, outData) != 0)
    {
        log<level::DEBUG>("Error in write JSON data to file");
        return -1;
    }

    // Update the timestamp
    voltFileLastUpdatedTime = getUpdatedFileTime(channelVolatileDataFilename);
    return 0;
}

int ChannelConfig::writeChannelPersistData()
{
    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        channelLock{*channelMutex};
    Json outData;

    try
    {
        for (uint8_t chNum = 0; chNum < maxIpmiChannels; chNum++)
        {
            if (getChannelSessionSupport(chNum) != EChannelSessSupported::none)
            {
                Json jsonObj;
                std::string chKey = std::to_string(chNum);
                std::string accModeStr = convertToAccessModeString(
                    channelData[chNum].chAccess.chNonVoltData.accessMode);
                jsonObj[accessModeString] = accModeStr;
                jsonObj[userAuthDisabledString] =
                    channelData[chNum].chAccess.chNonVoltData.userAuthDisabled;
                jsonObj[perMsgAuthDisabledString] =
                    channelData[chNum]
                        .chAccess.chNonVoltData.perMsgAuthDisabled;
                jsonObj[alertingDisabledString] =
                    channelData[chNum].chAccess.chNonVoltData.alertingDisabled;
                std::string privStr = convertToPrivLimitString(
                    channelData[chNum].chAccess.chNonVoltData.privLimit);
                jsonObj[privLimitString] = privStr;

                outData[chKey] = jsonObj;
            }
        }
    }
    catch (const std::invalid_argument& e)
    {
        log<level::ERR>("Corrupted config.", entry("MSG: %s", e.what()));
        return -1;
    }

    if (writeJsonFile(channelNvDataFilename, outData) != 0)
    {
        log<level::DEBUG>("Error in write JSON data to file");
        return -1;
    }

    // Update the timestamp
    nvFileLastUpdatedTime = getUpdatedFileTime(channelNvDataFilename);
    return 0;
}

int ChannelConfig::checkAndReloadNVData()
{
    std::time_t updateTime = getUpdatedFileTime(channelNvDataFilename);
    int ret = 0;
    if (updateTime != nvFileLastUpdatedTime || updateTime == -1)
    {
        try
        {
            ret = readChannelPersistData();
        }
        catch (const std::exception& e)
        {
            log<level::ERR>("Exception caught in readChannelPersistData.",
                            entry("MSG=%s", e.what()));
            ret = -1;
        }
    }
    return ret;
}

int ChannelConfig::checkAndReloadVoltData()
{
    std::time_t updateTime = getUpdatedFileTime(channelVolatileDataFilename);
    int ret = 0;
    if (updateTime != voltFileLastUpdatedTime || updateTime == -1)
    {
        try
        {
            ret = readChannelVolatileData();
        }
        catch (const std::exception& e)
        {
            log<level::ERR>("Exception caught in readChannelVolatileData.",
                            entry("MSG=%s", e.what()));
            ret = -1;
        }
    }
    return ret;
}

int ChannelConfig::setDbusProperty(sdbusplus::bus::bus& bus,
                                   const std::string& service,
                                   const std::string& objPath,
                                   const std::string& interface,
                                   const std::string& property,
                                   const DbusVariant& value)
{
    try
    {
        auto method =
            bus.new_method_call(service.c_str(), objPath.c_str(),
                                "org.freedesktop.DBus.Properties", "Set");

        method.append(interface, property, value);

        auto reply = bus.call(method);
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        log<level::DEBUG>("set-property failed",
                          entry("SERVICE:%s", service.c_str()),
                          entry("OBJPATH:%s", objPath.c_str()),
                          entry("INTERFACE:%s", interface.c_str()),
                          entry("PROP:%s", property.c_str()));
        return -1;
    }

    return 0;
}

int ChannelConfig::getDbusProperty(sdbusplus::bus::bus& bus,
                                   const std::string& service,
                                   const std::string& objPath,
                                   const std::string& interface,
                                   const std::string& property,
                                   DbusVariant& value)
{
    try
    {
        auto method =
            bus.new_method_call(service.c_str(), objPath.c_str(),
                                "org.freedesktop.DBus.Properties", "Get");

        method.append(interface, property);

        auto reply = bus.call(method);
        reply.read(value);
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        log<level::DEBUG>("get-property failed",
                          entry("SERVICE:%s", service.c_str()),
                          entry("OBJPATH:%s", objPath.c_str()),
                          entry("INTERFACE:%s", interface.c_str()),
                          entry("PROP:%s", property.c_str()));
        return -1;
    }
    return 0;
}

int ChannelConfig::syncNetworkChannelConfig()
{
    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        channelLock{*channelMutex};
    bool isUpdated = false;
    for (uint8_t chNum = 0; chNum < maxIpmiChannels; chNum++)
    {
        if (getChannelSessionSupport(chNum) != EChannelSessSupported::none)
        {
            std::string intfPrivStr;
            try
            {
                std::string intfName =
                    convertToNetInterface(channelData[chNum].chName);
                std::string networkIntfObj =
                    std::string(networkIntfObjectBasePath) + "/" + intfName;
                DbusVariant variant;
                if (0 != getDbusProperty(bus, networkIntfServiceName,
                                         networkIntfObj,
                                         networkChConfigIntfName,
                                         privilegePropertyString, variant))
                {
                    log<level::DEBUG>("Network interface does not exist",
                                      entry("INTERFACE:%s", intfName.c_str()));
                    continue;
                }
                intfPrivStr = variant.get<std::string>();
            }
            catch (const mapbox::util::bad_variant_access& e)
            {
                log<level::DEBUG>(
                    "exception: Network interface does not exist");
                continue;
            }
            catch (const sdbusplus::exception::SdBusError& e)
            {
                log<level::DEBUG>(
                    "exception: Network interface does not exist");
                continue;
            }

            uint8_t intfPriv =
                static_cast<uint8_t>(convertToPrivLimitIndex(intfPrivStr));
            if (channelData[chNum].chAccess.chNonVoltData.privLimit != intfPriv)
            {
                isUpdated = true;
                channelData[chNum].chAccess.chNonVoltData.privLimit = intfPriv;
                channelData[chNum].chAccess.chVoltData.privLimit = intfPriv;
            }
        }
    }

    if (isUpdated)
    {
        // Write persistant data to file
        if (writeChannelPersistData() != 0)
        {
            log<level::DEBUG>("Failed to update the presist data file");
            return -1;
        }
        // Write Volatile data to file
        if (writeChannelVolatileData() != 0)
        {
            log<level::DEBUG>("Failed to update the channel volatile data");
            return -1;
        }
    }

    return 0;
}

void ChannelConfig::initChannelPersistData()
{
    /* Always read the channel config */
    if (loadChannelConfig() != 0)
    {
        log<level::ERR>("Failed to read channel config file");
        throw std::ios_base::failure("Failed to load channel configuration");
    }

    /* Populate the channel persist data */
    if (readChannelPersistData() != 0)
    {
        // Copy default NV data to RW location
        std::experimental::filesystem::copy_file(channelAccessDefaultFilename,
                                                 channelNvDataFilename);

        // Load the channel access NV data
        if (readChannelPersistData() != 0)
        {
            log<level::ERR>("Failed to read channel access NV data");
            throw std::ios_base::failure(
                "Failed to read channel access NV configuration");
        }
    }

    // First check the volatile data file
    // If not present, load the default values
    if (readChannelVolatileData() != 0)
    {
        // Copy default volatile data to temporary location
        // NV file(channelNvDataFilename) must have created by now.
        std::experimental::filesystem::copy_file(channelNvDataFilename,
                                                 channelVolatileDataFilename);

        // Load the channel access volatile data
        if (readChannelVolatileData() != 0)
        {
            log<level::ERR>("Failed to read channel access volatile data");
            throw std::ios_base::failure(
                "Failed to read channel access volatile configuration");
        }
    }

    // Synchronize the channel config(priv) with network channel
    // configuration(priv) over dbus
    if (syncNetworkChannelConfig() != 0)
    {
        log<level::ERR>(
            "Failed to synchronize data with network channel config over dbus");
        throw std::ios_base::failure(
            "Failed to synchronize data with network channel config over dbus");
    }

    log<level::DEBUG>("Successfully completed channel data initialization.");
    return;
}

} // namespace ipmi
