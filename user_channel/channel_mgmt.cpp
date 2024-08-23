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

#include "apphandler.hpp"
#include "user_layer.hpp"

#include <ifaddrs.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <boost/interprocess/sync/scoped_lock.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/server/object.hpp>

#include <cerrno>
#include <exception>
#include <filesystem>
#include <fstream>
#include <unordered_map>

namespace ipmi
{

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
static constexpr const char* interfaceAddedSignal = "InterfacesAdded";
static constexpr const char* interfaceRemovedSignal = "InterfacesRemoved";

// STRING DEFINES: Should sync with key's in JSON
static constexpr const char* nameString = "name";
static constexpr const char* isValidString = "is_valid";
static constexpr const char* activeSessionsString = "active_sessions";
static constexpr const char* maxTransferSizeString = "max_transfer_size";
static constexpr const char* channelInfoString = "channel_info";
static constexpr const char* mediumTypeString = "medium_type";
static constexpr const char* protocolTypeString = "protocol_type";
static constexpr const char* sessionSupportedString = "session_supported";
static constexpr const char* isIpmiString = "is_ipmi";
static constexpr const char* isManagementNIC = "is_management_nic";
static constexpr const char* accessModeString = "access_mode";
static constexpr const char* userAuthDisabledString = "user_auth_disabled";
static constexpr const char* perMsgAuthDisabledString = "per_msg_auth_disabled";
static constexpr const char* alertingDisabledString = "alerting_disabled";
static constexpr const char* privLimitString = "priv_limit";

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
static constexpr size_t smallChannelSize = 64;

std::unique_ptr<sdbusplus::bus::match_t> chPropertiesSignal
    __attribute__((init_priority(101)));

std::unique_ptr<sdbusplus::bus::match_t> chInterfaceAddedSignal
    __attribute__((init_priority(101)));

std::unique_ptr<sdbusplus::bus::match_t> chInterfaceRemovedSignal
    __attribute__((init_priority(101)));

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

static std::unordered_map<EInterfaceIndex, std::string> interfaceMap = {
    {interfaceKCS, "SMS"},
    {interfaceLAN1, "eth0"},
    {interfaceUnknown, "unknown"}};

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

const std::array<std::string, PRIVILEGE_OEM + 1> privList = {
    "priv-reserved", "priv-callback", "priv-user",
    "priv-operator", "priv-admin",    "priv-oem"};

std::string ChannelConfig::getChannelName(const uint8_t chNum)
{
    if (!isValidChannel(chNum))
    {
        lg2::error("Invalid channel number: {CHANNEL_ID}", "CHANNEL_ID", chNum);
        throw std::invalid_argument("Invalid channel number");
    }

    return channelData[chNum].chName;
}

int ChannelConfig::convertToChannelNumberFromChannelName(
    const std::string& chName)
{
    for (const auto& it : channelData)
    {
        if (it.chName == chName)
        {
            return it.chID;
        }
    }
    lg2::error("Invalid channel name: {CHANNEL}", "CHANNEL", chName);
    throw std::invalid_argument("Invalid channel name");

    return -1;
}

std::string ChannelConfig::getChannelNameFromPath(const std::string& path)
{
    const size_t length = strlen(networkIntfObjectBasePath);
    if (((length + 1) >= path.size()) ||
        path.compare(0, length, networkIntfObjectBasePath))
    {
        lg2::error("Invalid object path: {PATH}", "PATH", path);
        throw std::invalid_argument("Invalid object path");
    }
    std::string chName(path, length + 1);
    return chName;
}

void ChannelConfig::processChAccessPropChange(
    const std::string& path, const DbusChObjProperties& chProperties)
{
    // Get interface name from path. ex: '/xyz/openbmc_project/network/eth0'
    std::string chName;
    try
    {
        chName = getChannelNameFromPath(path);
    }
    catch (const std::invalid_argument& e)
    {
        lg2::error("Exception: {MSG}", "MSG", e.what());
        return;
    }

    // Get the MaxPrivilege property value from the signal
    std::string intfPrivStr;
    std::string propName;
    for (const auto& prop : chProperties)
    {
        if (prop.first == privilegePropertyString)
        {
            propName = privilegePropertyString;
            intfPrivStr = std::get<std::string>(prop.second);
            break;
        }
    }

    if (propName != privilegePropertyString)
    {
        lg2::error("Unknown signal caught.");
        return;
    }

    if (intfPrivStr.empty())
    {
        lg2::error("Invalid privilege string for intf {INTF}", "INTF", chName);
        return;
    }

    uint8_t intfPriv = 0;
    int chNum;
    try
    {
        intfPriv = static_cast<uint8_t>(convertToPrivLimitIndex(intfPrivStr));
        chNum = convertToChannelNumberFromChannelName(chName);
    }
    catch (const std::invalid_argument& e)
    {
        lg2::error("Exception: {MSG}", "MSG", e.what());
        return;
    }

    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        channelLock{*channelMutex};
    // skip updating the values, if this property change originated from IPMI.
    if (signalFlag & (1 << chNum))
    {
        signalFlag &= ~(1 << chNum);
        lg2::debug("Request originated from IPMI so ignoring signal");
        return;
    }

    // Update both volatile & Non-volatile, if there is mismatch.
    // as property change other than IPMI, has to update both volatile &
    // non-volatile data.
    checkAndReloadVolatileData();
    checkAndReloadNVData();
    if (channelData[chNum].chAccess.chNonVolatileData.privLimit != intfPriv)
    {
        // Update NV data
        channelData[chNum].chAccess.chNonVolatileData.privLimit = intfPriv;
        if (writeChannelPersistData() != 0)
        {
            lg2::error("Failed to update the persist data file");
            return;
        }

        // Update Volatile data
        if (channelData[chNum].chAccess.chVolatileData.privLimit != intfPriv)
        {
            channelData[chNum].chAccess.chVolatileData.privLimit = intfPriv;
            if (writeChannelVolatileData() != 0)
            {
                lg2::error("Failed to update the volatile data file");
                return;
            }
        }
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
    if (signalHndlrObjectState)
    {
        chPropertiesSignal.reset();
        chInterfaceAddedSignal.reset();
        chInterfaceRemovedSignal.reset();
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
        lg2::debug("Unable to open mutex cleanup file");
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
    // Register it for single object and single process either netipmid /
    // host-ipmid
    if (chPropertiesSignal == nullptr && sigHndlrLock.try_lock())
    {
        lg2::debug("Registering channel signal handler.");
        chPropertiesSignal = std::make_unique<sdbusplus::bus::match_t>(
            bus,
            sdbusplus::bus::match::rules::path_namespace(
                networkIntfObjectBasePath) +
                sdbusplus::bus::match::rules::type::signal() +
                sdbusplus::bus::match::rules::member(propertiesChangedSignal) +
                sdbusplus::bus::match::rules::interface(
                    dBusPropertiesInterface) +
                sdbusplus::bus::match::rules::argN(0, networkChConfigIntfName),
            [&](sdbusplus::message_t& msg) {
                DbusChObjProperties props;
                std::string iface;
                std::string path = msg.get_path();
                msg.read(iface, props);
                processChAccessPropChange(path, props);
            });
        signalHndlrObjectState = true;

        chInterfaceAddedSignal = std::make_unique<sdbusplus::bus::match_t>(
            bus,
            sdbusplus::bus::match::rules::type::signal() +
                sdbusplus::bus::match::rules::member(interfaceAddedSignal) +
                sdbusplus::bus::match::rules::argNpath(
                    0, std::string(networkIntfObjectBasePath) + "/"),
            [&](sdbusplus::message_t&) { initChannelPersistData(); });

        chInterfaceRemovedSignal = std::make_unique<sdbusplus::bus::match_t>(
            bus,
            sdbusplus::bus::match::rules::type::signal() +
                sdbusplus::bus::match::rules::member(interfaceRemovedSignal) +
                sdbusplus::bus::match::rules::argNpath(
                    0, std::string(networkIntfObjectBasePath) + "/"),
            [&](sdbusplus::message_t&) { initChannelPersistData(); });
    }
}

bool ChannelConfig::isValidChannel(const uint8_t chNum)
{
    if (chNum >= maxIpmiChannels)
    {
        lg2::debug("Invalid channel ID - Out of range");
        return false;
    }

    if (channelData[chNum].isChValid == false)
    {
        lg2::debug("Channel is not valid");
    }

    return channelData[chNum].isChValid;
}

EChannelSessSupported
    ChannelConfig::getChannelSessionSupport(const uint8_t chNum)
{
    EChannelSessSupported chSessSupport =
        (EChannelSessSupported)channelData[chNum].chInfo.sessionSupported;
    return chSessSupport;
}

bool ChannelConfig::isValidAuthType(const uint8_t chNum,
                                    const EAuthType& authType)
{
    if ((authType < EAuthType::md2) || (authType > EAuthType::oem))
    {
        lg2::debug("Invalid authentication type");
        return false;
    }

    uint8_t authTypeSupported = channelData[chNum].chInfo.authTypeSupported;
    if (!(authTypeSupported & (1 << static_cast<uint8_t>(authType))))
    {
        lg2::debug("Authentication type is not supported.");
        return false;
    }

    return true;
}

int ChannelConfig::getChannelActiveSessions(const uint8_t chNum)
{
    // TODO: TEMPORARY FIX
    // Channels active session count is managed separately
    // by monitoring channel session which includes LAN and
    // RAKP layer changes. This will be updated, once the
    // authentication part is implemented.
    return channelData[chNum].activeSessCount;
}

size_t ChannelConfig::getChannelMaxTransferSize(uint8_t chNum)
{
    return channelData[chNum].maxTransferSize;
}

Cc ChannelConfig::getChannelInfo(const uint8_t chNum, ChannelInfo& chInfo)
{
    if (!isValidChannel(chNum))
    {
        lg2::debug("Invalid channel");
        return ccInvalidFieldRequest;
    }

    std::copy_n(reinterpret_cast<uint8_t*>(&channelData[chNum].chInfo),
                sizeof(channelData[chNum].chInfo),
                reinterpret_cast<uint8_t*>(&chInfo));
    return ccSuccess;
}

Cc ChannelConfig::getChannelAccessData(const uint8_t chNum,
                                       ChannelAccess& chAccessData)
{
    if (!isValidChannel(chNum))
    {
        lg2::debug("Invalid channel");
        return ccInvalidFieldRequest;
    }

    if (getChannelSessionSupport(chNum) == EChannelSessSupported::none)
    {
        lg2::debug("Session-less channel doesn't have access data.");
        return ccActionNotSupportedForChannel;
    }

    if (checkAndReloadVolatileData() != 0)
    {
        return ccUnspecifiedError;
    }

    std::copy_n(
        reinterpret_cast<uint8_t*>(&channelData[chNum].chAccess.chVolatileData),
        sizeof(channelData[chNum].chAccess.chVolatileData),
        reinterpret_cast<uint8_t*>(&chAccessData));

    return ccSuccess;
}

Cc ChannelConfig::setChannelAccessData(const uint8_t chNum,
                                       const ChannelAccess& chAccessData,
                                       const uint8_t setFlag)
{
    if (!isValidChannel(chNum))
    {
        lg2::debug("Invalid channel");
        return ccInvalidFieldRequest;
    }

    if (getChannelSessionSupport(chNum) == EChannelSessSupported::none)
    {
        lg2::debug("Session-less channel doesn't have access data.");
        return ccActionNotSupportedForChannel;
    }

    if ((setFlag & setAccessMode) &&
        (!isValidAccessMode(chAccessData.accessMode)))
    {
        lg2::debug("Invalid access mode specified");
        return ccAccessModeNotSupportedForChannel;
    }
    if ((setFlag & setPrivLimit) && (!isValidPrivLimit(chAccessData.privLimit)))
    {
        lg2::debug("Invalid privilege limit specified");
        return ccInvalidFieldRequest;
    }

    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        channelLock{*channelMutex};

    if (checkAndReloadVolatileData() != 0)
    {
        return ccUnspecifiedError;
    }

    if (setFlag & setAccessMode)
    {
        channelData[chNum].chAccess.chVolatileData.accessMode =
            chAccessData.accessMode;
    }
    if (setFlag & setUserAuthEnabled)
    {
        channelData[chNum].chAccess.chVolatileData.userAuthDisabled =
            chAccessData.userAuthDisabled;
    }
    if (setFlag & setMsgAuthEnabled)
    {
        channelData[chNum].chAccess.chVolatileData.perMsgAuthDisabled =
            chAccessData.perMsgAuthDisabled;
    }
    if (setFlag & setAlertingEnabled)
    {
        channelData[chNum].chAccess.chVolatileData.alertingDisabled =
            chAccessData.alertingDisabled;
    }
    if (setFlag & setPrivLimit)
    {
        channelData[chNum].chAccess.chVolatileData.privLimit =
            chAccessData.privLimit;
    }

    // Write Volatile data to file
    if (writeChannelVolatileData() != 0)
    {
        lg2::debug("Failed to update the channel volatile data");
        return ccUnspecifiedError;
    }
    return ccSuccess;
}

Cc ChannelConfig::getChannelAccessPersistData(const uint8_t chNum,
                                              ChannelAccess& chAccessData)
{
    if (!isValidChannel(chNum))
    {
        lg2::debug("Invalid channel");
        return ccInvalidFieldRequest;
    }

    if (getChannelSessionSupport(chNum) == EChannelSessSupported::none)
    {
        lg2::debug("Session-less channel doesn't have access data.");
        return ccActionNotSupportedForChannel;
    }

    if (checkAndReloadNVData() != 0)
    {
        return ccUnspecifiedError;
    }

    std::copy_n(reinterpret_cast<uint8_t*>(
                    &channelData[chNum].chAccess.chNonVolatileData),
                sizeof(channelData[chNum].chAccess.chNonVolatileData),
                reinterpret_cast<uint8_t*>(&chAccessData));

    return ccSuccess;
}

Cc ChannelConfig::setChannelAccessPersistData(const uint8_t chNum,
                                              const ChannelAccess& chAccessData,
                                              const uint8_t setFlag)
{
    if (!isValidChannel(chNum))
    {
        lg2::debug("Invalid channel");
        return ccInvalidFieldRequest;
    }

    if (getChannelSessionSupport(chNum) == EChannelSessSupported::none)
    {
        lg2::debug("Session-less channel doesn't have access data.");
        return ccActionNotSupportedForChannel;
    }

    if ((setFlag & setAccessMode) &&
        (!isValidAccessMode(chAccessData.accessMode)))
    {
        lg2::debug("Invalid access mode specified");
        return ccAccessModeNotSupportedForChannel;
    }
    if ((setFlag & setPrivLimit) && (!isValidPrivLimit(chAccessData.privLimit)))
    {
        lg2::debug("Invalid privilege limit specified");
        return ccInvalidFieldRequest;
    }

    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        channelLock{*channelMutex};

    if (checkAndReloadNVData() != 0)
    {
        return ccUnspecifiedError;
    }

    if (setFlag & setAccessMode)
    {
        channelData[chNum].chAccess.chNonVolatileData.accessMode =
            chAccessData.accessMode;
    }
    if (setFlag & setUserAuthEnabled)
    {
        channelData[chNum].chAccess.chNonVolatileData.userAuthDisabled =
            chAccessData.userAuthDisabled;
    }
    if (setFlag & setMsgAuthEnabled)
    {
        channelData[chNum].chAccess.chNonVolatileData.perMsgAuthDisabled =
            chAccessData.perMsgAuthDisabled;
    }
    if (setFlag & setAlertingEnabled)
    {
        channelData[chNum].chAccess.chNonVolatileData.alertingDisabled =
            chAccessData.alertingDisabled;
    }
    if (setFlag & setPrivLimit)
    {
        // Send Update to network channel config interfaces over dbus
        std::string privStr = convertToPrivLimitString(chAccessData.privLimit);
        std::string networkIntfObj = std::string(networkIntfObjectBasePath) +
                                     "/" + channelData[chNum].chName;
        try
        {
            if (0 != setDbusProperty(networkIntfServiceName, networkIntfObj,
                                     networkChConfigIntfName,
                                     privilegePropertyString, privStr))
            {
                lg2::debug("Network interface '{INTERFACE}' does not exist",
                           "INTERFACE", channelData[chNum].chName);
                return ccUnspecifiedError;
            }
        }
        catch (const sdbusplus::exception_t& e)
        {
            lg2::error("Exception: Network interface does not exist");
            return ccInvalidFieldRequest;
        }
        signalFlag |= (1 << chNum);
        channelData[chNum].chAccess.chNonVolatileData.privLimit =
            chAccessData.privLimit;
    }

    // Write persistent data to file
    if (writeChannelPersistData() != 0)
    {
        lg2::debug("Failed to update the presist data file");
        return ccUnspecifiedError;
    }
    return ccSuccess;
}

Cc ChannelConfig::getChannelAuthTypeSupported(const uint8_t chNum,
                                              uint8_t& authTypeSupported)
{
    if (!isValidChannel(chNum))
    {
        lg2::debug("Invalid channel");
        return ccInvalidFieldRequest;
    }

    authTypeSupported = channelData[chNum].chInfo.authTypeSupported;
    return ccSuccess;
}

Cc ChannelConfig::getChannelEnabledAuthType(
    const uint8_t chNum, const uint8_t priv, EAuthType& authType)
{
    if (!isValidChannel(chNum))
    {
        lg2::debug("Invalid channel");
        return ccInvalidFieldRequest;
    }

    if (getChannelSessionSupport(chNum) == EChannelSessSupported::none)
    {
        lg2::debug("Sessionless channel doesn't have access data.");
        return ccInvalidFieldRequest;
    }

    if (!isValidPrivLimit(priv))
    {
        lg2::debug("Invalid privilege specified.");
        return ccInvalidFieldRequest;
    }

    // TODO: Hardcoded for now. Need to implement.
    authType = EAuthType::none;

    return ccSuccess;
}

std::time_t ChannelConfig::getUpdatedFileTime(const std::string& fileName)
{
    struct stat fileStat;
    if (stat(fileName.c_str(), &fileStat) != 0)
    {
        lg2::debug("Error in getting last updated time stamp");
        return -EIO;
    }
    return fileStat.st_mtime;
}

EChannelAccessMode
    ChannelConfig::convertToAccessModeIndex(const std::string& mode)
{
    auto iter = std::find(accessModeList.begin(), accessModeList.end(), mode);
    if (iter == accessModeList.end())
    {
        lg2::error("Invalid access mode: {MODE_STR}", "MODE_STR", mode);
        throw std::invalid_argument("Invalid access mode.");
    }

    return static_cast<EChannelAccessMode>(
        std::distance(accessModeList.begin(), iter));
}

std::string ChannelConfig::convertToAccessModeString(const uint8_t value)
{
    if (accessModeList.size() <= value)
    {
        lg2::error("Invalid access mode: {MODE_IDX}", "MODE_IDX", value);
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
        lg2::error("Invalid privilege: {PRIV_STR}", "PRIV_STR", value);
        throw std::invalid_argument("Invalid privilege.");
    }

    return static_cast<CommandPrivilege>(std::distance(privList.begin(), iter));
}

std::string ChannelConfig::convertToPrivLimitString(const uint8_t value)
{
    if (privList.size() <= value)
    {
        lg2::error("Invalid privilege: {PRIV_IDX.", "PRIV_IDX", value);
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
        lg2::error("Invalid session supported: {SESS_STR}", "SESS_STR", value);
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
        lg2::error("Invalid medium type: {MEDIUM_STR}", "MEDIUM_STR", value);
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
        lg2::error("Invalid protocol type: {PROTO_STR}", "PROTO_STR", value);
        throw std::invalid_argument("Invalid protocol type.");
    }

    return static_cast<EChannelProtocolType>(it->second);
}

Json ChannelConfig::readJsonFile(const std::string& configFile)
{
    std::ifstream jsonFile(configFile);
    if (!jsonFile.good())
    {
        lg2::info("JSON file '{FILE_NAME}' not found", "FILE_NAME", configFile);
        return nullptr;
    }

    Json data = nullptr;
    try
    {
        data = Json::parse(jsonFile, nullptr, false);
    }
    catch (const Json::parse_error& e)
    {
        lg2::debug("Corrupted channel config: {MSG}", "MSG", e.what());
        throw std::runtime_error("Corrupted channel config file");
    }

    return data;
}

int ChannelConfig::writeJsonFile(const std::string& configFile,
                                 const Json& jsonData)
{
    const std::string tmpFile = configFile + "_tmp";
    int fd = open(tmpFile.c_str(), O_CREAT | O_WRONLY | O_TRUNC | O_SYNC,
                  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0)
    {
        lg2::error("Error in creating json file '{FILE_NAME}'", "FILE_NAME",
                   tmpFile);
        return -EIO;
    }
    const auto& writeData = jsonData.dump();
    if (write(fd, writeData.c_str(), writeData.size()) !=
        static_cast<ssize_t>(writeData.size()))
    {
        close(fd);
        lg2::error("Error in writing configuration file '{FILE_NAME}'",
                   "FILE_NAME", tmpFile);
        return -EIO;
    }
    close(fd);

    if (std::rename(tmpFile.c_str(), configFile.c_str()) != 0)
    {
        lg2::error("Error in renaming temporary data file '{FILE_NAME}'",
                   "FILE_NAME", tmpFile);
        return -EIO;
    }

    return 0;
}

void ChannelConfig::setDefaultChannelConfig(const uint8_t chNum,
                                            const std::string& chName)
{
    channelData[chNum].chName = chName;
    channelData[chNum].chID = chNum;
    channelData[chNum].isChValid = false;
    channelData[chNum].activeSessCount = 0;
    channelData[chNum].isManagementNIC = false;

    channelData[chNum].chInfo.mediumType = defaultMediumType;
    channelData[chNum].chInfo.protocolType = defaultProtocolType;
    channelData[chNum].chInfo.sessionSupported = defaultSessionSupported;
    channelData[chNum].chInfo.isIpmi = defaultIsIpmiState;
    channelData[chNum].chInfo.authTypeSupported = defaultAuthType;
}

uint8_t ChannelConfig::getManagementNICID()
{
    static bool idFound = false;
    static uint8_t id = 0;

    if (idFound)
    {
        return id;
    }

    for (uint8_t chIdx = 0; chIdx < maxIpmiChannels; chIdx++)
    {
        if (channelData[chIdx].isManagementNIC)
        {
            id = chIdx;
            idFound = true;
            break;
        }
    }

    if (!idFound)
    {
        id = static_cast<uint8_t>(EChannelID::chanLan1);
        idFound = true;
    }
    return id;
}

int ChannelConfig::loadChannelConfig()
{
    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        channelLock{*channelMutex};

    Json data = readJsonFile(channelConfigDefaultFilename);
    if (data.empty())
    {
        lg2::debug("Error in opening IPMI Channel data file");
        return -EIO;
    }

    channelData.fill(ChannelProperties{});

    // Collect the list of NIC interfaces connected to the BMC. Use this
    // information to only add IPMI channels that have active NIC interfaces.
    struct ifaddrs *ifaddr = nullptr, *ifa = nullptr;
    if (int err = getifaddrs(&ifaddr); err < 0)
    {
        lg2::debug("Unable to acquire network interfaces");
        return -EIO;
    }

    for (int chNum = 0; chNum < maxIpmiChannels; chNum++)
    {
        try
        {
            std::string chKey = std::to_string(chNum);
            Json jsonChData = data[chKey].get<Json>();
            if (jsonChData.is_null())
            {
                // If user didn't want to configure specific channel (say
                // reserved channel), then load that index with default values.
                setDefaultChannelConfig(chNum, defaultChannelName);
                continue;
            }
            Json jsonChInfo = jsonChData[channelInfoString].get<Json>();
            if (jsonChInfo.is_null())
            {
                lg2::error("Invalid/corrupted channel config file");
                freeifaddrs(ifaddr);
                return -EBADMSG;
            }

            bool channelFound = true;
            // Confirm the LAN channel is present
            if (jsonChInfo[mediumTypeString].get<std::string>() == "lan-802.3")
            {
                channelFound = false;
                for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
                {
                    if (jsonChData[nameString].get<std::string>() ==
                        ifa->ifa_name)
                    {
                        channelFound = true;
                        break;
                    }
                }
            }
            ChannelProperties& chData = channelData[chNum];
            chData.chID = chNum;
            chData.chName = jsonChData[nameString].get<std::string>();
            chData.isChValid = channelFound &&
                               jsonChData[isValidString].get<bool>();
            chData.activeSessCount = jsonChData.value(activeSessionsString, 0);
            chData.maxTransferSize =
                jsonChData.value(maxTransferSizeString, smallChannelSize);
            if (jsonChData.count(isManagementNIC) != 0)
            {
                chData.isManagementNIC =
                    jsonChData[isManagementNIC].get<bool>();
            }

            std::string medTypeStr =
                jsonChInfo[mediumTypeString].get<std::string>();
            chData.chInfo.mediumType =
                static_cast<uint8_t>(convertToMediumTypeIndex(medTypeStr));
            std::string protoTypeStr =
                jsonChInfo[protocolTypeString].get<std::string>();
            chData.chInfo.protocolType =
                static_cast<uint8_t>(convertToProtocolTypeIndex(protoTypeStr));
            std::string sessStr =
                jsonChInfo[sessionSupportedString].get<std::string>();
            chData.chInfo.sessionSupported =
                static_cast<uint8_t>(convertToSessionSupportIndex(sessStr));
            chData.chInfo.isIpmi = jsonChInfo[isIpmiString].get<bool>();
            chData.chInfo.authTypeSupported = defaultAuthType;
        }
        catch (const Json::exception& e)
        {
            lg2::debug("Json Exception caught: {MSG}", "MSG", e.what());
            freeifaddrs(ifaddr);

            return -EBADMSG;
        }
        catch (const std::invalid_argument& e)
        {
            lg2::error("Corrupted config: {MSG}", "MSG", e.what());
            freeifaddrs(ifaddr);
            return -EBADMSG;
        }
    }
    freeifaddrs(ifaddr);

    return 0;
}

int ChannelConfig::readChannelVolatileData()
{
    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        channelLock{*channelMutex};

    Json data = readJsonFile(channelVolatileDataFilename);
    if (data == nullptr)
    {
        lg2::debug("Error in opening IPMI Channel data file");
        return -EIO;
    }
    try
    {
        // Fill in global structure
        for (auto it = data.begin(); it != data.end(); ++it)
        {
            std::string chKey = it.key();
            uint8_t chNum = std::stoi(chKey, nullptr, 10);
            if (chNum >= maxIpmiChannels)
            {
                lg2::debug("Invalid channel access entry in config file");
                throw std::out_of_range("Out of range - channel number");
            }
            Json jsonChData = it.value();
            if (!jsonChData.is_null())
            {
                std::string accModeStr =
                    jsonChData[accessModeString].get<std::string>();
                channelData[chNum].chAccess.chVolatileData.accessMode =
                    static_cast<uint8_t>(convertToAccessModeIndex(accModeStr));
                channelData[chNum].chAccess.chVolatileData.userAuthDisabled =
                    jsonChData[userAuthDisabledString].get<bool>();
                channelData[chNum].chAccess.chVolatileData.perMsgAuthDisabled =
                    jsonChData[perMsgAuthDisabledString].get<bool>();
                channelData[chNum].chAccess.chVolatileData.alertingDisabled =
                    jsonChData[alertingDisabledString].get<bool>();
                std::string privStr =
                    jsonChData[privLimitString].get<std::string>();
                channelData[chNum].chAccess.chVolatileData.privLimit =
                    static_cast<uint8_t>(convertToPrivLimitIndex(privStr));
            }
            else
            {
                lg2::error(
                    "Invalid/corrupted volatile channel access file '{FILE}'",
                    "FILE", channelVolatileDataFilename);
                throw std::runtime_error(
                    "Corrupted volatile channel access file");
            }
        }
    }
    catch (const Json::exception& e)
    {
        lg2::debug("Json Exception caught: {MSG}", "MSG", e.what());
        throw std::runtime_error("Corrupted volatile channel access file");
    }
    catch (const std::invalid_argument& e)
    {
        lg2::error("Corrupted config: {MSG}", "MSG", e.what());
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
        lg2::debug("Error in opening IPMI Channel data file");
        return -EIO;
    }
    try
    {
        // Fill in global structure
        for (auto it = data.begin(); it != data.end(); ++it)
        {
            std::string chKey = it.key();
            uint8_t chNum = std::stoi(chKey, nullptr, 10);
            if (chNum >= maxIpmiChannels)
            {
                lg2::debug("Invalid channel access entry in config file");
                throw std::out_of_range("Out of range - channel number");
            }
            Json jsonChData = it.value();
            if (!jsonChData.is_null())
            {
                std::string accModeStr =
                    jsonChData[accessModeString].get<std::string>();
                channelData[chNum].chAccess.chNonVolatileData.accessMode =
                    static_cast<uint8_t>(convertToAccessModeIndex(accModeStr));
                channelData[chNum].chAccess.chNonVolatileData.userAuthDisabled =
                    jsonChData[userAuthDisabledString].get<bool>();
                channelData[chNum]
                    .chAccess.chNonVolatileData.perMsgAuthDisabled =
                    jsonChData[perMsgAuthDisabledString].get<bool>();
                channelData[chNum].chAccess.chNonVolatileData.alertingDisabled =
                    jsonChData[alertingDisabledString].get<bool>();
                std::string privStr =
                    jsonChData[privLimitString].get<std::string>();
                channelData[chNum].chAccess.chNonVolatileData.privLimit =
                    static_cast<uint8_t>(convertToPrivLimitIndex(privStr));
            }
            else
            {
                lg2::error("Invalid/corrupted nv channel access file {FILE}",
                           "FILE", channelNvDataFilename);
                throw std::runtime_error("Corrupted nv channel access file");
            }
        }
    }
    catch (const Json::exception& e)
    {
        lg2::debug("Json Exception caught: {MSG}", "MSG", e.what());
        throw std::runtime_error("Corrupted nv channel access file");
    }
    catch (const std::invalid_argument& e)
    {
        lg2::error("Corrupted config: {MSG}", "MSG", e.what());
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
                    channelData[chNum].chAccess.chVolatileData.accessMode);
                jsonObj[accessModeString] = accModeStr;
                jsonObj[userAuthDisabledString] =
                    channelData[chNum].chAccess.chVolatileData.userAuthDisabled;
                jsonObj[perMsgAuthDisabledString] =
                    channelData[chNum]
                        .chAccess.chVolatileData.perMsgAuthDisabled;
                jsonObj[alertingDisabledString] =
                    channelData[chNum].chAccess.chVolatileData.alertingDisabled;
                std::string privStr = convertToPrivLimitString(
                    channelData[chNum].chAccess.chVolatileData.privLimit);
                jsonObj[privLimitString] = privStr;

                outData[chKey] = jsonObj;
            }
        }
    }
    catch (const std::invalid_argument& e)
    {
        lg2::error("Corrupted config: {MSG}", "MSG", e.what());
        return -EINVAL;
    }

    if (writeJsonFile(channelVolatileDataFilename, outData) != 0)
    {
        lg2::debug("Error in write JSON data to file");
        return -EIO;
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
                    channelData[chNum].chAccess.chNonVolatileData.accessMode);
                jsonObj[accessModeString] = accModeStr;
                jsonObj[userAuthDisabledString] =
                    channelData[chNum]
                        .chAccess.chNonVolatileData.userAuthDisabled;
                jsonObj[perMsgAuthDisabledString] =
                    channelData[chNum]
                        .chAccess.chNonVolatileData.perMsgAuthDisabled;
                jsonObj[alertingDisabledString] =
                    channelData[chNum]
                        .chAccess.chNonVolatileData.alertingDisabled;
                std::string privStr = convertToPrivLimitString(
                    channelData[chNum].chAccess.chNonVolatileData.privLimit);
                jsonObj[privLimitString] = privStr;

                outData[chKey] = jsonObj;
            }
        }
    }
    catch (const std::invalid_argument& e)
    {
        lg2::error("Corrupted config: {MSG}", "MSG", e.what());
        return -EINVAL;
    }

    if (writeJsonFile(channelNvDataFilename, outData) != 0)
    {
        lg2::debug("Error in write JSON data to file");
        return -EIO;
    }

    // Update the timestamp
    nvFileLastUpdatedTime = getUpdatedFileTime(channelNvDataFilename);
    return 0;
}

int ChannelConfig::checkAndReloadNVData()
{
    std::time_t updateTime = getUpdatedFileTime(channelNvDataFilename);
    int ret = 0;
    if (updateTime != nvFileLastUpdatedTime || updateTime == -EIO)
    {
        try
        {
            ret = readChannelPersistData();
        }
        catch (const std::exception& e)
        {
            lg2::error("Exception caught in readChannelPersistData: {MSG}",
                       "MSG", e.what());
            ret = -EIO;
        }
    }
    return ret;
}

int ChannelConfig::checkAndReloadVolatileData()
{
    std::time_t updateTime = getUpdatedFileTime(channelVolatileDataFilename);
    int ret = 0;
    if (updateTime != voltFileLastUpdatedTime || updateTime == -EIO)
    {
        try
        {
            ret = readChannelVolatileData();
        }
        catch (const std::exception& e)
        {
            lg2::error("Exception caught in readChannelVolatileData: {MSG}",
                       "MSG", e.what());
            ret = -EIO;
        }
    }
    return ret;
}

int ChannelConfig::setDbusProperty(
    const std::string& service, const std::string& objPath,
    const std::string& interface, const std::string& property,
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
    catch (const sdbusplus::exception_t& e)
    {
        lg2::debug(
            "set-property {SERVICE}:{OBJPATH}/{INTERFACE}.{PROP} failed: {MSG}",
            "SERVICE", service, "OBJPATH", objPath, "INTERFACE", interface,
            "PROP", property);
        return -EIO;
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
            uint8_t intfPriv = 0;
            try
            {
                std::string networkIntfObj =
                    std::string(networkIntfObjectBasePath) + "/" +
                    channelData[chNum].chName;
                auto propValue = ipmi::getDbusProperty(
                    bus, networkIntfServiceName, networkIntfObj,
                    networkChConfigIntfName, privilegePropertyString);

                intfPrivStr = std::get<std::string>(propValue);
                intfPriv =
                    static_cast<uint8_t>(convertToPrivLimitIndex(intfPrivStr));
            }
            catch (const std::bad_variant_access& e)
            {
                lg2::debug("Network interface '{INTERFACE}' does not exist",
                           "INTERFACE", channelData[chNum].chName);
                continue;
            }
            catch (const sdbusplus::exception_t& e)
            {
                lg2::debug("Network interface '{INTERFACE}' does not exist",
                           "INTERFACE", channelData[chNum].chName);
                continue;
            }
            catch (const std::invalid_argument& e)
            {
                lg2::debug("exception: Invalid privilege");
                continue;
            }

            if (channelData[chNum].chAccess.chNonVolatileData.privLimit !=
                intfPriv)
            {
                isUpdated = true;
                channelData[chNum].chAccess.chNonVolatileData.privLimit =
                    intfPriv;
                channelData[chNum].chAccess.chVolatileData.privLimit = intfPriv;
            }
        }
    }

    if (isUpdated)
    {
        // Write persistent data to file
        if (writeChannelPersistData() != 0)
        {
            lg2::debug("Failed to update the persistent data file");
            return -EIO;
        }
        // Write Volatile data to file
        if (writeChannelVolatileData() != 0)
        {
            lg2::debug("Failed to update the channel volatile data");
            return -EIO;
        }
    }

    return 0;
}

void ChannelConfig::initChannelPersistData()
{
    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        channelLock{*channelMutex};

    /* Always read the channel config */
    if (loadChannelConfig() != 0)
    {
        lg2::error("Failed to read channel config file");
        throw std::ios_base::failure("Failed to load channel configuration");
    }

    /* Populate the channel persist data */
    if (readChannelPersistData() != 0)
    {
        // Copy default NV data to RW location
        std::filesystem::copy_file(channelAccessDefaultFilename,
                                   channelNvDataFilename);

        // Load the channel access NV data
        if (readChannelPersistData() != 0)
        {
            lg2::error("Failed to read channel access NV data");
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
        std::filesystem::copy_file(channelNvDataFilename,
                                   channelVolatileDataFilename);

        // Load the channel access volatile data
        if (readChannelVolatileData() != 0)
        {
            lg2::error("Failed to read channel access volatile data");
            throw std::ios_base::failure(
                "Failed to read channel access volatile configuration");
        }
    }

    // Synchronize the channel config(priv) with network channel
    // configuration(priv) over dbus
    if (syncNetworkChannelConfig() != 0)
    {
        lg2::error(
            "Failed to synchronize data with network channel config over dbus");
        throw std::ios_base::failure(
            "Failed to synchronize data with network channel config over dbus");
    }

    lg2::debug("Successfully completed channel data initialization.");
    return;
}

} // namespace ipmi
