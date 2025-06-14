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
#include "user_mgmt.hpp"

#include "channel_layer.hpp"
#include "channel_mgmt.hpp"

#include <security/pam_appl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <boost/interprocess/sync/named_recursive_mutex.hpp>
#include <boost/interprocess/sync/scoped_lock.hpp>
#include <ipmid/types.hpp>
#include <nlohmann/json.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/User/Common/error.hpp>

#include <cerrno>
#include <fstream>
#include <regex>
#include <variant>

namespace ipmi
{

// TODO: Move D-Bus & Object Manager related stuff, to common files
// D-Bus property related
static constexpr const char* dBusPropertiesInterface =
    "org.freedesktop.DBus.Properties";
static constexpr const char* getAllPropertiesMethod = "GetAll";
static constexpr const char* propertiesChangedSignal = "PropertiesChanged";
static constexpr const char* setPropertiesMethod = "Set";

// Object Manager related
static constexpr const char* dBusObjManager =
    "org.freedesktop.DBus.ObjectManager";
static constexpr const char* getManagedObjectsMethod = "GetManagedObjects";
// Object Manager signals
static constexpr const char* intfAddedSignal = "InterfacesAdded";
static constexpr const char* intfRemovedSignal = "InterfacesRemoved";

static constexpr const char* ipmiUserMutex = "ipmi_usr_mutex";
static constexpr const char* ipmiMutexCleanupLockFile =
    "/run/ipmi/ipmi_usr_mutex_cleanup";
static constexpr const char* ipmiUserSignalLockFile =
    "/run/ipmi/ipmi_usr_signal_mutex";
static constexpr const char* ipmiUserDataFile = "/var/lib/ipmi/ipmi_user.json";
static constexpr const char* ipmiGrpName = "ipmi";
static constexpr size_t privNoAccess = 0xF;
static constexpr size_t privMask = 0xF;

// User manager related
static constexpr const char* userMgrService =
    "xyz.openbmc_project.User.Manager";
static constexpr const char* userMgrObjBasePath = "/xyz/openbmc_project/user";
static constexpr const char* userObjBasePath = "/xyz/openbmc_project/user";
static constexpr const char* userMgrInterface =
    "xyz.openbmc_project.User.Manager";
static constexpr const char* usersInterface =
    "xyz.openbmc_project.User.Attributes";
static constexpr const char* deleteUserInterface =
    "xyz.openbmc_project.Object.Delete";

static constexpr const char* createUserMethod = "CreateUser";
static constexpr const char* deleteUserMethod = "Delete";
static constexpr const char* renameUserMethod = "RenameUser";
// User manager signal memebers
static constexpr const char* userRenamedSignal = "UserRenamed";
// Mgr interface properties
static constexpr const char* allPrivProperty = "AllPrivileges";
static constexpr const char* allGrpProperty = "AllGroups";
// User interface properties
static constexpr const char* userPrivProperty = "UserPrivilege";
static constexpr const char* userGrpProperty = "UserGroups";
static constexpr const char* userEnabledProperty = "UserEnabled";

static std::array<std::string, (PRIVILEGE_OEM + 1)> ipmiPrivIndex = {
    "priv-reserved", // PRIVILEGE_RESERVED - 0
    "priv-callback", // PRIVILEGE_CALLBACK - 1
    "priv-user",     // PRIVILEGE_USER - 2
    "priv-operator", // PRIVILEGE_OPERATOR - 3
    "priv-admin",    // PRIVILEGE_ADMIN - 4
    "priv-custom"    // PRIVILEGE_OEM - 5
};

using namespace phosphor::logging;
using Json = nlohmann::json;

using PrivAndGroupType = std::variant<std::string, std::vector<std::string>>;

using NoResource =
    sdbusplus::error::xyz::openbmc_project::user::common::NoResource;

using InternalFailure =
    sdbusplus::error::xyz::openbmc_project::common::InternalFailure;

std::unique_ptr<sdbusplus::bus::match_t> userUpdatedSignal
    __attribute__((init_priority(101)));
std::unique_ptr<sdbusplus::bus::match_t> userMgrRenamedSignal
    __attribute__((init_priority(101)));
std::unique_ptr<sdbusplus::bus::match_t> userPropertiesSignal
    __attribute__((init_priority(101)));

void setDbusProperty(sdbusplus::bus_t& bus, const std::string& service,
                     const std::string& objPath, const std::string& interface,
                     const std::string& property,
                     const DbusUserPropVariant& value)
{
    try
    {
        auto method =
            bus.new_method_call(service.c_str(), objPath.c_str(),
                                dBusPropertiesInterface, setPropertiesMethod);
        method.append(interface, property, value);
        bus.call(method);
    }
    catch (const sdbusplus::exception_t& e)
    {
        lg2::error("Failed to set {PROPERTY}, path: {PATH}, "
                   "interface: {INTERFACE}",
                   "PROPERTY", property, "PATH", objPath, "INTERFACE",
                   interface);
        throw;
    }
}

UserAccess& getUserAccessObject()
{
    static UserAccess userAccess;
    return userAccess;
}

int getUserNameFromPath(const std::string& path, std::string& userName)
{
    sdbusplus::message::object_path objPath(path);
    userName.assign(objPath.filename());
    return 0;
}

void userUpdateHelper(UserAccess& usrAccess, const UserUpdateEvent& userEvent,
                      const std::string& userName, const std::string& priv,
                      const bool& enabled, const std::string& newUserName)
{
    UsersTbl* userData = usrAccess.getUsersTblPtr();
    if (userEvent == UserUpdateEvent::userCreated)
    {
        if (usrAccess.addUserEntry(userName, priv, enabled) == false)
        {
            return;
        }
    }
    else
    {
        // user index 0 is reserved, starts with 1
        size_t usrIndex = 1;
        for (; usrIndex <= ipmiMaxUsers; ++usrIndex)
        {
            std::string curName(
                reinterpret_cast<char*>(userData->user[usrIndex].userName), 0,
                ipmiMaxUserName);
            if (userName == curName)
            {
                break; // found the entry
            }
        }
        if (usrIndex > ipmiMaxUsers)
        {
            lg2::debug("User not found for signal, user name: {USER_NAME}, "
                       "user event: {USER_EVENT}",
                       "USER_NAME", userName, "USER_EVENT", userEvent);
            return;
        }
        switch (userEvent)
        {
            case UserUpdateEvent::userDeleted:
            {
                usrAccess.deleteUserIndex(usrIndex);
                break;
            }
            case UserUpdateEvent::userPrivUpdated:
            {
                uint8_t userPriv =
                    static_cast<uint8_t>(
                        UserAccess::convertToIPMIPrivilege(priv)) &
                    privMask;
                // Update all channels privileges, only if it is not equivalent
                // to getUsrMgmtSyncIndex()
                if (userData->user[usrIndex]
                        .userPrivAccess[UserAccess::getUsrMgmtSyncIndex()]
                        .privilege != userPriv)
                {
                    for (size_t chIndex = 0; chIndex < ipmiMaxChannels;
                         ++chIndex)
                    {
                        userData->user[usrIndex]
                            .userPrivAccess[chIndex]
                            .privilege = userPriv;
                    }
                }
                break;
            }
            case UserUpdateEvent::userRenamed:
            {
                std::fill(
                    static_cast<uint8_t*>(userData->user[usrIndex].userName),
                    static_cast<uint8_t*>(userData->user[usrIndex].userName) +
                        sizeof(userData->user[usrIndex].userName),
                    0);
                std::strncpy(
                    reinterpret_cast<char*>(userData->user[usrIndex].userName),
                    newUserName.c_str(), ipmiMaxUserName);
                ipmiRenameUserEntryPassword(userName, newUserName);
                break;
            }
            case UserUpdateEvent::userStateUpdated:
            {
                userData->user[usrIndex].userEnabled = enabled;
                break;
            }
            default:
            {
                lg2::error("Unhandled user event: {USER_EVENT}", "USER_EVENT",
                           userEvent);
                return;
            }
        }
    }
    usrAccess.writeUserData();
    lg2::debug("User event handled successfully, user name: {USER_NAME}, "
               "user event: {USER_EVENT}",
               "USER_NAME", userName.c_str(), "USER_EVENT", userEvent);

    return;
}

void userUpdatedSignalHandler(UserAccess& usrAccess, sdbusplus::message_t& msg)
{
    static sdbusplus::bus_t bus(ipmid_get_sd_bus_connection());
    std::string signal = msg.get_member();
    std::string userName, priv, newUserName;
    std::vector<std::string> groups;
    bool enabled = false;
    UserUpdateEvent userEvent = UserUpdateEvent::reservedEvent;
    if (signal == intfAddedSignal)
    {
        DbusUserObjPath objPath;
        DbusUserObjValue objValue;
        msg.read(objPath, objValue);
        getUserNameFromPath(objPath.str, userName);
        if (usrAccess.getUserObjProperties(objValue, groups, priv, enabled) !=
            0)
        {
            return;
        }
        if (std::find(groups.begin(), groups.end(), ipmiGrpName) ==
            groups.end())
        {
            return;
        }
        userEvent = UserUpdateEvent::userCreated;
    }
    else if (signal == intfRemovedSignal)
    {
        DbusUserObjPath objPath;
        std::vector<std::string> interfaces;
        msg.read(objPath, interfaces);
        getUserNameFromPath(objPath.str, userName);
        userEvent = UserUpdateEvent::userDeleted;
    }
    else if (signal == userRenamedSignal)
    {
        msg.read(userName, newUserName);
        userEvent = UserUpdateEvent::userRenamed;
    }
    else if (signal == propertiesChangedSignal)
    {
        getUserNameFromPath(msg.get_path(), userName);
    }
    else
    {
        lg2::error("Unknown user update signal: {SIGNAL}", "SIGNAL", signal);
        return;
    }

    if (signal.empty() || userName.empty() ||
        (signal == userRenamedSignal && newUserName.empty()))
    {
        lg2::error("Invalid inputs received");
        return;
    }

    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        userLock{*(usrAccess.userMutex)};
    usrAccess.checkAndReloadUserData();

    if (signal == propertiesChangedSignal)
    {
        std::string intfName;
        DbusUserObjProperties chProperties;
        msg.read(intfName, chProperties); // skip reading 3rd argument.
        for (const auto& prop : chProperties)
        {
            userEvent = UserUpdateEvent::reservedEvent;
            std::string member = prop.first;
            if (member == userPrivProperty)
            {
                priv = std::get<std::string>(prop.second);
                userEvent = UserUpdateEvent::userPrivUpdated;
            }
            else if (member == userGrpProperty)
            {
                groups = std::get<std::vector<std::string>>(prop.second);
                userEvent = UserUpdateEvent::userGrpUpdated;
            }
            else if (member == userEnabledProperty)
            {
                enabled = std::get<bool>(prop.second);
                userEvent = UserUpdateEvent::userStateUpdated;
            }
            // Process based on event type.
            if (userEvent == UserUpdateEvent::userGrpUpdated)
            {
                if (std::find(groups.begin(), groups.end(), ipmiGrpName) ==
                    groups.end())
                {
                    // remove user from ipmi user list.
                    userUpdateHelper(usrAccess, UserUpdateEvent::userDeleted,
                                     userName, priv, enabled, newUserName);
                }
                else
                {
                    DbusUserObjProperties properties;
                    try
                    {
                        auto method = bus.new_method_call(
                            userMgrService, msg.get_path(),
                            dBusPropertiesInterface, getAllPropertiesMethod);
                        method.append(usersInterface);
                        auto reply = bus.call(method);
                        reply.read(properties);
                    }
                    catch (const sdbusplus::exception_t& e)
                    {
                        lg2::debug("Failed to excute {METHOD}, path: {PATH}",
                                   "METHOD", getAllPropertiesMethod, "PATH",
                                   msg.get_path());
                        return;
                    }
                    usrAccess.getUserProperties(properties, groups, priv,
                                                enabled);
                    // add user to ipmi user list.
                    userUpdateHelper(usrAccess, UserUpdateEvent::userCreated,
                                     userName, priv, enabled, newUserName);
                }
            }
            else if (userEvent != UserUpdateEvent::reservedEvent)
            {
                userUpdateHelper(usrAccess, userEvent, userName, priv, enabled,
                                 newUserName);
            }
        }
    }
    else if (userEvent != UserUpdateEvent::reservedEvent)
    {
        userUpdateHelper(usrAccess, userEvent, userName, priv, enabled,
                         newUserName);
    }
    return;
}

UserAccess::~UserAccess()
{
    if (signalHndlrObject)
    {
        userUpdatedSignal.reset();
        userMgrRenamedSignal.reset();
        userPropertiesSignal.reset();
        sigHndlrLock.unlock();
    }
}

UserAccess::UserAccess() : bus(ipmid_get_sd_bus_connection())
{
    std::ofstream mutexCleanUpFile;
    mutexCleanUpFile.open(ipmiMutexCleanupLockFile,
                          std::ofstream::out | std::ofstream::app);
    if (!mutexCleanUpFile.good())
    {
        lg2::debug("Unable to open mutex cleanup file");
        return;
    }
    mutexCleanUpFile.close();
    mutexCleanupLock = boost::interprocess::file_lock(ipmiMutexCleanupLockFile);
    if (mutexCleanupLock.try_lock())
    {
        boost::interprocess::named_recursive_mutex::remove(ipmiUserMutex);
    }
    mutexCleanupLock.lock_sharable();
    userMutex = std::make_unique<boost::interprocess::named_recursive_mutex>(
        boost::interprocess::open_or_create, ipmiUserMutex);

    cacheUserDataFile();
    getSystemPrivAndGroups();
}

UserInfo* UserAccess::getUserInfo(const uint8_t userId)
{
    checkAndReloadUserData();
    return &usersTbl.user[userId];
}

void UserAccess::setUserInfo(const uint8_t userId, UserInfo* userInfo)
{
    checkAndReloadUserData();
    std::copy(reinterpret_cast<uint8_t*>(userInfo),
              reinterpret_cast<uint8_t*>(userInfo) + sizeof(*userInfo),
              reinterpret_cast<uint8_t*>(&usersTbl.user[userId]));
    writeUserData();
}

bool UserAccess::isValidChannel(const uint8_t chNum)
{
    return (chNum < ipmiMaxChannels);
}

bool UserAccess::isValidUserId(const uint8_t userId)
{
    return ((userId <= ipmiMaxUsers) && (userId != reservedUserId));
}

bool UserAccess::isValidPrivilege(const uint8_t priv)
{
    // Callback privilege is deprecated in OpenBMC
    return isValidPrivLimit(priv);
}

uint8_t UserAccess::getUsrMgmtSyncIndex()
{
    // Identify the IPMI channel used to assign system user privilege levels
    // in phosphor-user-manager. The default value is IPMI Channel 1. To
    // assign a different channel add:
    //      "is_management_nic" : true
    // into the channel_config.json file describing the assignment of the IPMI
    // channels. It is only necessary to add the string above to ONE record in
    // the channel_config.json file. All other records will be automatically
    // assigned a "false" value.
    return getChannelConfigObject().getManagementNICID();
}

CommandPrivilege UserAccess::convertToIPMIPrivilege(const std::string& value)
{
    auto iter = std::find(ipmiPrivIndex.begin(), ipmiPrivIndex.end(), value);
    if (iter == ipmiPrivIndex.end())
    {
        if (value == "")
        {
            return static_cast<CommandPrivilege>(privNoAccess);
        }
        lg2::error("Error in converting to IPMI privilege: {PRIV}", "PRIV",
                   value);
        throw std::out_of_range("Out of range - convertToIPMIPrivilege");
    }
    else
    {
        return static_cast<CommandPrivilege>(
            std::distance(ipmiPrivIndex.begin(), iter));
    }
}

std::string UserAccess::convertToSystemPrivilege(const CommandPrivilege& value)
{
    if (value == static_cast<CommandPrivilege>(privNoAccess))
    {
        return "";
    }
    try
    {
        return ipmiPrivIndex.at(value);
    }
    catch (const std::out_of_range& e)
    {
        lg2::error("Error in converting to system privilege: {PRIV}", "PRIV",
                   value);
        throw std::out_of_range("Out of range - convertToSystemPrivilege");
    }
}

bool UserAccess::isValidUserName(const std::string& userName)
{
    if (userName.empty())
    {
        lg2::error("userName is empty");
        return false;
    }
    if (!std::regex_match(userName.c_str(),
                          std::regex("[a-zA-Z_][a-zA-Z_0-9]*")))
    {
        lg2::error("Unsupported characters in user name");
        return false;
    }
    if (userName == "root")
    {
        lg2::error("Invalid user name - root");
        return false;
    }
    std::map<DbusUserObjPath, DbusUserObjValue> properties;
    try
    {
        auto method =
            bus.new_method_call(userMgrService, userMgrObjBasePath,
                                dBusObjManager, getManagedObjectsMethod);
        auto reply = bus.call(method);
        reply.read(properties);
    }
    catch (const sdbusplus::exception_t& e)
    {
        lg2::error("Failed to excute {METHOD}, path: {PATH}", "METHOD",
                   getManagedObjectsMethod, "PATH", userMgrObjBasePath);
        return false;
    }

    sdbusplus::message::object_path tempUserPath(userObjBasePath);
    tempUserPath /= userName;
    std::string usersPath(tempUserPath);

    if (properties.find(usersPath) != properties.end())
    {
        lg2::debug("Username {USER_NAME} already exists", "USER_NAME",
                   userName);
        return false;
    }

    return true;
}

/** @brief Information exchanged by pam module and application.
 *
 *  @param[in] numMsg - length of the array of pointers,msg.
 *
 *  @param[in] msg -  pointer  to an array of pointers to pam_message structure
 *
 *  @param[out] resp - struct pam response array
 *
 *  @param[in] appdataPtr - member of pam_conv structure
 *
 *  @return the response in pam response structure.
 */

static int pamFunctionConversation(int numMsg, const struct pam_message** msg,
                                   struct pam_response** resp, void* appdataPtr)
{
    if (appdataPtr == nullptr)
    {
        return PAM_CONV_ERR;
    }

    if (numMsg <= 0 || numMsg >= PAM_MAX_NUM_MSG)
    {
        return PAM_CONV_ERR;
    }

    for (int i = 0; i < numMsg; ++i)
    {
        /* Ignore all PAM messages except prompting for hidden input */
        if (msg[i]->msg_style != PAM_PROMPT_ECHO_OFF)
        {
            continue;
        }

        /* Assume PAM is only prompting for the password as hidden input */
        /* Allocate memory only when PAM_PROMPT_ECHO_OFF is encounterred */

        char* appPass = reinterpret_cast<char*>(appdataPtr);
        size_t appPassSize = std::strlen(appPass);

        if (appPassSize >= PAM_MAX_RESP_SIZE)
        {
            return PAM_CONV_ERR;
        }

        char* pass = reinterpret_cast<char*>(malloc(appPassSize + 1));
        if (pass == nullptr)
        {
            return PAM_BUF_ERR;
        }

        void* ptr =
            calloc(static_cast<size_t>(numMsg), sizeof(struct pam_response));
        if (ptr == nullptr)
        {
            free(pass);
            return PAM_BUF_ERR;
        }

        std::strncpy(pass, appPass, appPassSize + 1);

        *resp = reinterpret_cast<pam_response*>(ptr);
        resp[i]->resp = pass;

        return PAM_SUCCESS;
    }

    return PAM_CONV_ERR;
}

/** @brief Updating the PAM password
 *
 *  @param[in] username - username in string
 *
 *  @param[in] password  - new password in string
 *
 *  @return status
 */

int pamUpdatePasswd(const char* username, const char* password)
{
    const struct pam_conv localConversation = {pamFunctionConversation,
                                               const_cast<char*>(password)};
    pam_handle_t* localAuthHandle = nullptr; // this gets set by pam_start

    int retval =
        pam_start("passwd", username, &localConversation, &localAuthHandle);

    if (retval != PAM_SUCCESS)
    {
        return retval;
    }

    retval = pam_chauthtok(localAuthHandle, PAM_SILENT);
    if (retval != PAM_SUCCESS)
    {
        pam_end(localAuthHandle, retval);
        return retval;
    }

    return pam_end(localAuthHandle, PAM_SUCCESS);
}

bool pamUserCheckAuthenticate(std::string_view username,
                              std::string_view password)
{
    const struct pam_conv localConversation = {
        pamFunctionConversation, const_cast<char*>(password.data())};

    pam_handle_t* localAuthHandle = nullptr; // this gets set by pam_start

    if (pam_start("dropbear", username.data(), &localConversation,
                  &localAuthHandle) != PAM_SUCCESS)
    {
        lg2::error("User Authentication Failure");
        return false;
    }

    int retval = pam_authenticate(localAuthHandle,
                                  PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK);

    if (retval != PAM_SUCCESS)
    {
        lg2::debug("pam_authenticate returned failure: {ERROR}", "ERROR",
                   retval);

        pam_end(localAuthHandle, retval);
        return false;
    }

    if (pam_acct_mgmt(localAuthHandle, PAM_DISALLOW_NULL_AUTHTOK) !=
        PAM_SUCCESS)
    {
        pam_end(localAuthHandle, PAM_SUCCESS);
        return false;
    }

    if (pam_end(localAuthHandle, PAM_SUCCESS) != PAM_SUCCESS)
    {
        return false;
    }
    return true;
}

Cc UserAccess::setSpecialUserPassword(const std::string& userName,
                                      const SecureString& userPassword)
{
    if (pamUpdatePasswd(userName.c_str(), userPassword.c_str()) != PAM_SUCCESS)
    {
        lg2::debug("Failed to update password");
        return ccUnspecifiedError;
    }
    return ccSuccess;
}

Cc UserAccess::setUserPassword(const uint8_t userId, const char* userPassword)
{
    std::string userName;
    if (ipmiUserGetUserName(userId, userName) != ccSuccess)
    {
        lg2::debug("User Name not found, user Id: {USER_ID}", "USER_ID",
                   userId);
        return ccParmOutOfRange;
    }

    ipmi::SecureString passwd;
    passwd.assign(reinterpret_cast<const char*>(userPassword), 0,
                  maxIpmi20PasswordSize);
    int retval = pamUpdatePasswd(userName.c_str(), passwd.c_str());

    switch (retval)
    {
        case PAM_SUCCESS:
        {
            return ccSuccess;
        }
        case PAM_AUTHTOK_ERR:
        {
            lg2::debug("Bad authentication token");
            return ccInvalidFieldRequest;
        }
        default:
        {
            lg2::debug("Failed to update password, user Id: {USER_ID}",
                       "USER_ID", userId);
            return ccUnspecifiedError;
        }
    }
}

Cc UserAccess::setUserEnabledState(const uint8_t userId,
                                   const bool& enabledState)
{
    if (!isValidUserId(userId))
    {
        return ccParmOutOfRange;
    }
    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        userLock{*userMutex};
    UserInfo* userInfo = getUserInfo(userId);
    std::string userName;
    userName.assign(reinterpret_cast<char*>(userInfo->userName), 0,
                    ipmiMaxUserName);
    if (userName.empty())
    {
        lg2::debug("User name not set / invalid");
        return ccUnspecifiedError;
    }
    if (userInfo->userEnabled != enabledState)
    {
        sdbusplus::message::object_path tempUserPath(userObjBasePath);
        tempUserPath /= userName;
        std::string userPath(tempUserPath);
        setDbusProperty(bus, userMgrService, userPath, usersInterface,
                        userEnabledProperty, enabledState);
        userInfo->userEnabled = enabledState;
        try
        {
            writeUserData();
        }
        catch (const std::exception& e)
        {
            lg2::debug("Write user data failed");
            return ccUnspecifiedError;
        }
    }
    return ccSuccess;
}

Cc UserAccess::setUserPayloadAccess(
    const uint8_t chNum, const uint8_t operation, const uint8_t userId,
    const PayloadAccess& payloadAccess)
{
    constexpr uint8_t enable = 0x0;
    constexpr uint8_t disable = 0x1;

    if (!isValidChannel(chNum))
    {
        lg2::debug(
            "Set user payload access - Invalid channel request: {CHANNEL}",
            "CHANNEL", chNum);
        return ccInvalidFieldRequest;
    }
    if (!isValidUserId(userId))
    {
        return ccParmOutOfRange;
    }
    if (operation != enable && operation != disable)
    {
        return ccInvalidFieldRequest;
    }
    // Check operation & payloadAccess if required.
    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        userLock{*userMutex};
    UserInfo* userInfo = getUserInfo(userId);

    if (operation == enable)
    {
        userInfo->payloadAccess[chNum].stdPayloadEnables1 |=
            payloadAccess.stdPayloadEnables1;

        userInfo->payloadAccess[chNum].oemPayloadEnables1 |=
            payloadAccess.oemPayloadEnables1;
    }
    else
    {
        userInfo->payloadAccess[chNum].stdPayloadEnables1 &=
            ~(payloadAccess.stdPayloadEnables1);

        userInfo->payloadAccess[chNum].oemPayloadEnables1 &=
            ~(payloadAccess.oemPayloadEnables1);
    }

    try
    {
        writeUserData();
    }
    catch (const std::exception& e)
    {
        lg2::error("Write user data failed");
        return ccUnspecifiedError;
    }
    return ccSuccess;
}

Cc UserAccess::setUserPrivilegeAccess(const uint8_t userId, const uint8_t chNum,
                                      const UserPrivAccess& privAccess,
                                      const bool& otherPrivUpdates)
{
    if (!isValidChannel(chNum))
    {
        lg2::debug(
            "Set user privilege access - Invalid channel request: {CHANNEL}",
            "CHANNEL", chNum);
        return ccInvalidFieldRequest;
    }
    if (!isValidUserId(userId))
    {
        return ccParmOutOfRange;
    }
    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        userLock{*userMutex};
    UserInfo* userInfo = getUserInfo(userId);
    std::string userName;
    userName.assign(reinterpret_cast<char*>(userInfo->userName), 0,
                    ipmiMaxUserName);
    if (userName.empty())
    {
        lg2::debug("User name not set / invalid");
        return ccUnspecifiedError;
    }
    std::string priv = convertToSystemPrivilege(
        static_cast<CommandPrivilege>(privAccess.privilege));
    uint8_t syncIndex = getUsrMgmtSyncIndex();
    if (chNum == syncIndex &&
        privAccess.privilege != userInfo->userPrivAccess[syncIndex].privilege)
    {
        sdbusplus::message::object_path tempUserPath(userObjBasePath);
        tempUserPath /= userName;
        std::string userPath(tempUserPath);
        setDbusProperty(bus, userMgrService, userPath, usersInterface,
                        userPrivProperty, priv);
    }
    userInfo->userPrivAccess[chNum].privilege = privAccess.privilege;

    if (otherPrivUpdates)
    {
        userInfo->userPrivAccess[chNum].ipmiEnabled = privAccess.ipmiEnabled;
        userInfo->userPrivAccess[chNum].linkAuthEnabled =
            privAccess.linkAuthEnabled;
        userInfo->userPrivAccess[chNum].accessCallback =
            privAccess.accessCallback;
    }
    try
    {
        writeUserData();
    }
    catch (const std::exception& e)
    {
        lg2::debug("Write user data failed");
        return ccUnspecifiedError;
    }
    return ccSuccess;
}

uint8_t UserAccess::getUserId(const std::string& userName)
{
    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        userLock{*userMutex};
    checkAndReloadUserData();
    // user index 0 is reserved, starts with 1
    size_t usrIndex = 1;
    for (; usrIndex <= ipmiMaxUsers; ++usrIndex)
    {
        std::string curName(
            reinterpret_cast<char*>(usersTbl.user[usrIndex].userName), 0,
            ipmiMaxUserName);
        if (userName == curName)
        {
            break; // found the entry
        }
    }
    if (usrIndex > ipmiMaxUsers)
    {
        lg2::debug("Username {USER_NAME} not found", "USER_NAME", userName);
        return invalidUserId;
    }

    return usrIndex;
}

Cc UserAccess::getUserName(const uint8_t userId, std::string& userName)
{
    if (!isValidUserId(userId))
    {
        return ccParmOutOfRange;
    }
    UserInfo* userInfo = getUserInfo(userId);
    userName.assign(reinterpret_cast<char*>(userInfo->userName), 0,
                    ipmiMaxUserName);
    return ccSuccess;
}

bool UserAccess::isIpmiInAvailableGroupList()
{
    if (std::find(availableGroups.begin(), availableGroups.end(),
                  ipmiGrpName) != availableGroups.end())
    {
        return true;
    }
    if (availableGroups.empty())
    {
        // available groups shouldn't be empty, re-query
        getSystemPrivAndGroups();
        if (std::find(availableGroups.begin(), availableGroups.end(),
                      ipmiGrpName) != availableGroups.end())
        {
            return true;
        }
    }
    return false;
}

Cc UserAccess::setUserName(const uint8_t userId, const std::string& userName)
{
    if (!isValidUserId(userId))
    {
        return ccParmOutOfRange;
    }

    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        userLock{*userMutex};
    std::string oldUser;
    getUserName(userId, oldUser);

    if (oldUser == userName)
    {
        // requesting to set the same user name, return success.
        return ccSuccess;
    }

    bool validUser = isValidUserName(userName);
    UserInfo* userInfo = getUserInfo(userId);
    if (userName.empty() && !oldUser.empty())
    {
        // Delete existing user
        sdbusplus::message::object_path tempUserPath(userObjBasePath);
        tempUserPath /= oldUser;
        std::string userPath(tempUserPath);
        try
        {
            auto method =
                bus.new_method_call(userMgrService, userPath.c_str(),
                                    deleteUserInterface, deleteUserMethod);
            auto reply = bus.call(method);
        }
        catch (const sdbusplus::exception_t& e)
        {
            lg2::debug("Failed to excute {METHOD}, path:{PATH}", "METHOD",
                       deleteUserMethod, "PATH", userPath);
            return ccUnspecifiedError;
        }
        deleteUserIndex(userId);
    }
    else if (oldUser.empty() && !userName.empty() && validUser)
    {
        try
        {
            if (!isIpmiInAvailableGroupList())
            {
                return ccUnspecifiedError;
            }
            // Create new user
            auto method =
                bus.new_method_call(userMgrService, userMgrObjBasePath,
                                    userMgrInterface, createUserMethod);
            method.append(userName.c_str(), availableGroups,
                          ipmiPrivIndex[PRIVILEGE_USER], false);
            auto reply = bus.call(method);
        }
        catch (const sdbusplus::exception_t& e)
        {
            lg2::debug("Failed to excute {METHOD}, path: {PATH}", "METHOD",
                       createUserMethod, "PATH", userMgrObjBasePath);
            return ccUnspecifiedError;
        }

        std::memset(userInfo->userName, 0, sizeof(userInfo->userName));
        std::memcpy(userInfo->userName,
                    static_cast<const void*>(userName.data()), userName.size());
        userInfo->userInSystem = true;
        for (size_t chIndex = 0; chIndex < ipmiMaxChannels; chIndex++)
        {
            userInfo->userPrivAccess[chIndex].privilege =
                static_cast<uint8_t>(PRIVILEGE_USER);
        }
    }
    else if (oldUser != userName && validUser)
    {
        try
        {
            // User rename
            auto method =
                bus.new_method_call(userMgrService, userMgrObjBasePath,
                                    userMgrInterface, renameUserMethod);
            method.append(oldUser.c_str(), userName.c_str());
            auto reply = bus.call(method);
        }
        catch (const sdbusplus::exception_t& e)
        {
            lg2::debug("Failed to excute {METHOD}, path: {PATH}", "METHOD",
                       renameUserMethod, "PATH", userMgrObjBasePath);
            return ccUnspecifiedError;
        }
        std::fill(static_cast<uint8_t*>(userInfo->userName),
                  static_cast<uint8_t*>(userInfo->userName) +
                      sizeof(userInfo->userName),
                  0);

        std::memset(userInfo->userName, 0, sizeof(userInfo->userName));
        std::memcpy(userInfo->userName,
                    static_cast<const void*>(userName.data()), userName.size());

        ipmiRenameUserEntryPassword(oldUser, userName);
        userInfo->userInSystem = true;
    }
    else if (!validUser)
    {
        return ccInvalidFieldRequest;
    }
    try
    {
        writeUserData();
    }
    catch (const std::exception& e)
    {
        lg2::debug("Write user data failed");
        return ccUnspecifiedError;
    }
    return ccSuccess;
}

static constexpr const char* jsonUserName = "user_name";
static constexpr const char* jsonPriv = "privilege";
static constexpr const char* jsonIpmiEnabled = "ipmi_enabled";
static constexpr const char* jsonLinkAuthEnabled = "link_auth_enabled";
static constexpr const char* jsonAccCallbk = "access_callback";
static constexpr const char* jsonUserEnabled = "user_enabled";
static constexpr const char* jsonUserInSys = "user_in_system";
static constexpr const char* jsonFixedUser = "fixed_user_name";
static constexpr const char* payloadEnabledStr = "payload_enabled";
static constexpr const char* stdPayloadStr = "std_payload";
static constexpr const char* oemPayloadStr = "OEM_payload";

/** @brief to construct a JSON object from the given payload access details.
 *
 *  @param[in] stdPayload - stdPayloadEnables1 in a 2D-array. (input)
 *  @param[in] oemPayload - oemPayloadEnables1 in a 2D-array. (input)
 *
 *  @details Sample output JSON object format :
 *  "payload_enabled":{
 *  "OEM_payload0":[false,...<repeat 'ipmiMaxChannels - 1' times>],
 *  "OEM_payload1":[false,...<repeat 'ipmiMaxChannels - 1' times>],
 *  "OEM_payload2":[false,...<repeat 'ipmiMaxChannels - 1' times>],
 *  "OEM_payload3":[false,...<repeat 'ipmiMaxChannels - 1' times>],
 *  "OEM_payload4":[false,...<repeat 'ipmiMaxChannels - 1' times>],
 *  "OEM_payload5":[false,...<repeat 'ipmiMaxChannels - 1' times>],
 *  "OEM_payload6":[false,...<repeat 'ipmiMaxChannels - 1' times>],
 *  "OEM_payload7":[false,...<repeat 'ipmiMaxChannels - 1' times>],
 *  "std_payload0":[false,...<repeat 'ipmiMaxChannels - 1' times>],
 *  "std_payload1":[false,...<repeat 'ipmiMaxChannels - 1' times>],
 *  "std_payload2":[false,...<repeat 'ipmiMaxChannels - 1' times>],
 *  "std_payload3":[false,...<repeat 'ipmiMaxChannels - 1' times>],
 *  "std_payload4":[false,...<repeat 'ipmiMaxChannels - 1' times>],
 *  "std_payload5":[false,...<repeat 'ipmiMaxChannels - 1' times>],
 *  "std_payload6":[false,...<repeat 'ipmiMaxChannels - 1' times>],
 *  "std_payload7":[false,...<repeat 'ipmiMaxChannels - 1' times>],
 *  }
 */
static const Json constructJsonPayloadEnables(
    const std::array<std::array<bool, ipmiMaxChannels>, payloadsPerByte>&
        stdPayload,
    const std::array<std::array<bool, ipmiMaxChannels>, payloadsPerByte>&
        oemPayload)
{
    Json jsonPayloadEnabled;

    for (auto payloadNum = 0; payloadNum < payloadsPerByte; payloadNum++)
    {
        std::ostringstream stdPayloadStream;
        std::ostringstream oemPayloadStream;

        stdPayloadStream << stdPayloadStr << payloadNum;
        oemPayloadStream << oemPayloadStr << payloadNum;

        jsonPayloadEnabled.push_back(Json::object_t::value_type(
            stdPayloadStream.str(), stdPayload[payloadNum]));

        jsonPayloadEnabled.push_back(Json::object_t::value_type(
            oemPayloadStream.str(), oemPayload[payloadNum]));
    }
    return jsonPayloadEnabled;
}

void UserAccess::readPayloadAccessFromUserInfo(
    const UserInfo& userInfo,
    std::array<std::array<bool, ipmiMaxChannels>, payloadsPerByte>& stdPayload,
    std::array<std::array<bool, ipmiMaxChannels>, payloadsPerByte>& oemPayload)
{
    for (auto payloadNum = 0; payloadNum < payloadsPerByte; payloadNum++)
    {
        for (auto chIndex = 0; chIndex < ipmiMaxChannels; chIndex++)
        {
            stdPayload[payloadNum][chIndex] =
                userInfo.payloadAccess[chIndex].stdPayloadEnables1[payloadNum];

            oemPayload[payloadNum][chIndex] =
                userInfo.payloadAccess[chIndex].oemPayloadEnables1[payloadNum];
        }
    }
}

void UserAccess::updatePayloadAccessInUserInfo(
    const std::array<std::array<bool, ipmiMaxChannels>, payloadsPerByte>&
        stdPayload,
    const std::array<std::array<bool, ipmiMaxChannels>, payloadsPerByte>&,
    UserInfo& userInfo)
{
    for (size_t chIndex = 0; chIndex < ipmiMaxChannels; ++chIndex)
    {
        // Ensure that reserved/unsupported payloads are marked to zero.
        userInfo.payloadAccess[chIndex].stdPayloadEnables1.reset();
        userInfo.payloadAccess[chIndex].oemPayloadEnables1.reset();
        userInfo.payloadAccess[chIndex].stdPayloadEnables2Reserved.reset();
        userInfo.payloadAccess[chIndex].oemPayloadEnables2Reserved.reset();
        // Update SOL status as it is the only supported payload currently.
        userInfo.payloadAccess[chIndex]
            .stdPayloadEnables1[static_cast<uint8_t>(ipmi::PayloadType::SOL)] =
            stdPayload[static_cast<uint8_t>(ipmi::PayloadType::SOL)][chIndex];
    }
}

void UserAccess::readUserData()
{
    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        userLock{*userMutex};

    std::ifstream iUsrData(ipmiUserDataFile, std::ios::in | std::ios::binary);
    if (!iUsrData.good())
    {
        lg2::error("Error in reading IPMI user data file");
        throw std::ios_base::failure("Error opening IPMI user data file");
    }

    Json jsonUsersTbl = Json::array();
    jsonUsersTbl = Json::parse(iUsrData, nullptr, false);

    if (jsonUsersTbl.size() != ipmiMaxUsers)
    {
        lg2::error("Error in reading IPMI user data file - User count issues");
        throw std::runtime_error(
            "Corrupted IPMI user data file - invalid user count");
    }

    // user index 0 is reserved, starts with 1
    for (size_t usrIndex = 1; usrIndex <= ipmiMaxUsers; ++usrIndex)
    {
        Json userInfo = jsonUsersTbl[usrIndex - 1]; // json array starts with 0.
        if (userInfo.is_null())
        {
            lg2::error("Error in reading IPMI user data file - "
                       "user info corrupted");
            throw std::runtime_error(
                "Corrupted IPMI user data file - invalid user info");
        }
        std::string userName = userInfo[jsonUserName].get<std::string>();
        std::strncpy(reinterpret_cast<char*>(usersTbl.user[usrIndex].userName),
                     userName.c_str(), ipmiMaxUserName);

        std::vector<std::string> privilege =
            userInfo[jsonPriv].get<std::vector<std::string>>();
        std::vector<bool> ipmiEnabled =
            userInfo[jsonIpmiEnabled].get<std::vector<bool>>();
        std::vector<bool> linkAuthEnabled =
            userInfo[jsonLinkAuthEnabled].get<std::vector<bool>>();
        std::vector<bool> accessCallback =
            userInfo[jsonAccCallbk].get<std::vector<bool>>();

        // Payload Enables Processing.
        std::array<std::array<bool, ipmiMaxChannels>, payloadsPerByte>
            stdPayload = {};
        std::array<std::array<bool, ipmiMaxChannels>, payloadsPerByte>
            oemPayload = {};
        try
        {
            const auto jsonPayloadEnabled = userInfo.at(payloadEnabledStr);
            for (auto payloadNum = 0; payloadNum < payloadsPerByte;
                 payloadNum++)
            {
                std::ostringstream stdPayloadStream;
                std::ostringstream oemPayloadStream;

                stdPayloadStream << stdPayloadStr << payloadNum;
                oemPayloadStream << oemPayloadStr << payloadNum;

                stdPayload[payloadNum] =
                    jsonPayloadEnabled[stdPayloadStream.str()]
                        .get<std::array<bool, ipmiMaxChannels>>();
                oemPayload[payloadNum] =
                    jsonPayloadEnabled[oemPayloadStream.str()]
                        .get<std::array<bool, ipmiMaxChannels>>();

                if (stdPayload[payloadNum].size() != ipmiMaxChannels ||
                    oemPayload[payloadNum].size() != ipmiMaxChannels)
                {
                    lg2::error("Error in reading IPMI user data file - "
                               "payload properties corrupted");
                    throw std::runtime_error(
                        "Corrupted IPMI user data file - payload properties");
                }
            }
        }
        catch (const Json::out_of_range& e)
        {
            // Key not found in 'userInfo'; possibly an old JSON file. Use
            // default values for all payloads, and SOL payload default is true.
            stdPayload[static_cast<uint8_t>(ipmi::PayloadType::SOL)].fill(true);
        }

        if (privilege.size() != ipmiMaxChannels ||
            ipmiEnabled.size() != ipmiMaxChannels ||
            linkAuthEnabled.size() != ipmiMaxChannels ||
            accessCallback.size() != ipmiMaxChannels)
        {
            lg2::error("Error in reading IPMI user data file - "
                       "properties corrupted");
            throw std::runtime_error(
                "Corrupted IPMI user data file - properties");
        }
        for (size_t chIndex = 0; chIndex < ipmiMaxChannels; ++chIndex)
        {
            usersTbl.user[usrIndex].userPrivAccess[chIndex].privilege =
                static_cast<uint8_t>(
                    convertToIPMIPrivilege(privilege[chIndex]));
            usersTbl.user[usrIndex].userPrivAccess[chIndex].ipmiEnabled =
                ipmiEnabled[chIndex];
            usersTbl.user[usrIndex].userPrivAccess[chIndex].linkAuthEnabled =
                linkAuthEnabled[chIndex];
            usersTbl.user[usrIndex].userPrivAccess[chIndex].accessCallback =
                accessCallback[chIndex];
        }
        updatePayloadAccessInUserInfo(stdPayload, oemPayload,
                                      usersTbl.user[usrIndex]);
        usersTbl.user[usrIndex].userEnabled =
            userInfo[jsonUserEnabled].get<bool>();
        usersTbl.user[usrIndex].userInSystem =
            userInfo[jsonUserInSys].get<bool>();
        usersTbl.user[usrIndex].fixedUserName =
            userInfo[jsonFixedUser].get<bool>();
    }

    lg2::debug("User data read from IPMI data file");
    iUsrData.close();
    // Update the timestamp
    fileLastUpdatedTime = getUpdatedFileTime();
    return;
}

void UserAccess::writeUserData()
{
    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        userLock{*userMutex};

    Json jsonUsersTbl = Json::array();
    // user index 0 is reserved, starts with 1
    for (size_t usrIndex = 1; usrIndex <= ipmiMaxUsers; ++usrIndex)
    {
        Json jsonUserInfo;
        jsonUserInfo[jsonUserName] = std::string(
            reinterpret_cast<char*>(usersTbl.user[usrIndex].userName), 0,
            ipmiMaxUserName);
        std::vector<std::string> privilege(ipmiMaxChannels);
        std::vector<bool> ipmiEnabled(ipmiMaxChannels);
        std::vector<bool> linkAuthEnabled(ipmiMaxChannels);
        std::vector<bool> accessCallback(ipmiMaxChannels);

        std::array<std::array<bool, ipmiMaxChannels>, payloadsPerByte>
            stdPayload;
        std::array<std::array<bool, ipmiMaxChannels>, payloadsPerByte>
            oemPayload;

        for (size_t chIndex = 0; chIndex < ipmiMaxChannels; chIndex++)
        {
            privilege[chIndex] =
                convertToSystemPrivilege(static_cast<CommandPrivilege>(
                    usersTbl.user[usrIndex].userPrivAccess[chIndex].privilege));
            ipmiEnabled[chIndex] =
                usersTbl.user[usrIndex].userPrivAccess[chIndex].ipmiEnabled;
            linkAuthEnabled[chIndex] =
                usersTbl.user[usrIndex].userPrivAccess[chIndex].linkAuthEnabled;
            accessCallback[chIndex] =
                usersTbl.user[usrIndex].userPrivAccess[chIndex].accessCallback;
        }
        jsonUserInfo[jsonPriv] = privilege;
        jsonUserInfo[jsonIpmiEnabled] = ipmiEnabled;
        jsonUserInfo[jsonLinkAuthEnabled] = linkAuthEnabled;
        jsonUserInfo[jsonAccCallbk] = accessCallback;
        jsonUserInfo[jsonUserEnabled] = usersTbl.user[usrIndex].userEnabled;
        jsonUserInfo[jsonUserInSys] = usersTbl.user[usrIndex].userInSystem;
        jsonUserInfo[jsonFixedUser] = usersTbl.user[usrIndex].fixedUserName;

        readPayloadAccessFromUserInfo(usersTbl.user[usrIndex], stdPayload,
                                      oemPayload);
        Json jsonPayloadEnabledInfo =
            constructJsonPayloadEnables(stdPayload, oemPayload);
        jsonUserInfo[payloadEnabledStr] = jsonPayloadEnabledInfo;

        jsonUsersTbl.push_back(jsonUserInfo);
    }

    static std::string tmpFile{std::string(ipmiUserDataFile) + "_tmp"};
    int fd = open(tmpFile.c_str(), O_CREAT | O_WRONLY | O_TRUNC | O_SYNC,
                  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0)
    {
        lg2::error("Error in creating temporary IPMI user data file");
        throw std::ios_base::failure(
            "Error in creating temporary IPMI user data file");
    }
    const auto& writeStr = jsonUsersTbl.dump();
    if (write(fd, writeStr.c_str(), writeStr.size()) !=
        static_cast<ssize_t>(writeStr.size()))
    {
        close(fd);
        lg2::error("Error in writing temporary IPMI user data file");
        throw std::ios_base::failure(
            "Error in writing temporary IPMI user data file");
    }
    close(fd);

    if (std::rename(tmpFile.c_str(), ipmiUserDataFile) != 0)
    {
        lg2::error("Error in renaming temporary IPMI user data file");
        throw std::runtime_error("Error in renaming IPMI user data file");
    }
    // Update the timestamp
    fileLastUpdatedTime = getUpdatedFileTime();
    return;
}

bool UserAccess::addUserEntry(const std::string& userName,
                              const std::string& sysPriv, const bool& enabled)
{
    UsersTbl* userData = getUsersTblPtr();
    size_t freeIndex = 0xFF;
    // user index 0 is reserved, starts with 1
    for (size_t usrIndex = 1; usrIndex <= ipmiMaxUsers; ++usrIndex)
    {
        std::string curName(
            reinterpret_cast<char*>(userData->user[usrIndex].userName), 0,
            ipmiMaxUserName);
        if (userName == curName)
        {
            lg2::debug("Username {USER_NAME} exists", "USER_NAME", userName);
            return false; // user name exists.
        }

        if ((!userData->user[usrIndex].userInSystem) &&
            (userData->user[usrIndex].userName[0] == '\0') &&
            (freeIndex == 0xFF))
        {
            freeIndex = usrIndex;
        }
    }
    if (freeIndex == 0xFF)
    {
        lg2::error("No empty slots found");
        return false;
    }
    std::strncpy(reinterpret_cast<char*>(userData->user[freeIndex].userName),
                 userName.c_str(), ipmiMaxUserName);
    uint8_t priv =
        static_cast<uint8_t>(UserAccess::convertToIPMIPrivilege(sysPriv)) &
        privMask;
    for (size_t chIndex = 0; chIndex < ipmiMaxChannels; ++chIndex)
    {
        userData->user[freeIndex].userPrivAccess[chIndex].privilege = priv;
        userData->user[freeIndex].userPrivAccess[chIndex].ipmiEnabled = true;
        userData->user[freeIndex].userPrivAccess[chIndex].linkAuthEnabled =
            true;
        userData->user[freeIndex].userPrivAccess[chIndex].accessCallback = true;
    }
    userData->user[freeIndex].userInSystem = true;
    userData->user[freeIndex].userEnabled = enabled;

    return true;
}

void UserAccess::deleteUserIndex(const size_t& usrIdx)
{
    UsersTbl* userData = getUsersTblPtr();

    std::string userName(
        reinterpret_cast<char*>(userData->user[usrIdx].userName), 0,
        ipmiMaxUserName);
    ipmiClearUserEntryPassword(userName);
    std::fill(static_cast<uint8_t*>(userData->user[usrIdx].userName),
              static_cast<uint8_t*>(userData->user[usrIdx].userName) +
                  sizeof(userData->user[usrIdx].userName),
              0);
    for (size_t chIndex = 0; chIndex < ipmiMaxChannels; ++chIndex)
    {
        userData->user[usrIdx].userPrivAccess[chIndex].privilege = privNoAccess;
        userData->user[usrIdx].userPrivAccess[chIndex].ipmiEnabled = false;
        userData->user[usrIdx].userPrivAccess[chIndex].linkAuthEnabled = false;
        userData->user[usrIdx].userPrivAccess[chIndex].accessCallback = false;
    }
    userData->user[usrIdx].userInSystem = false;
    userData->user[usrIdx].userEnabled = false;
    return;
}

void UserAccess::checkAndReloadUserData()
{
    std::timespec updateTime = getUpdatedFileTime();
    if ((updateTime.tv_sec != fileLastUpdatedTime.tv_sec ||
         updateTime.tv_nsec != fileLastUpdatedTime.tv_nsec) ||
        (updateTime.tv_sec == 0 && updateTime.tv_nsec == 0))
    {
        std::fill(reinterpret_cast<uint8_t*>(&usersTbl),
                  reinterpret_cast<uint8_t*>(&usersTbl) + sizeof(usersTbl), 0);
        readUserData();
    }
    return;
}

UsersTbl* UserAccess::getUsersTblPtr()
{
    // reload data before using it.
    checkAndReloadUserData();
    return &usersTbl;
}

void UserAccess::getSystemPrivAndGroups()
{
    std::map<std::string, PrivAndGroupType> properties;
    try
    {
        auto method = bus.new_method_call(userMgrService, userMgrObjBasePath,
                                          dBusPropertiesInterface,
                                          getAllPropertiesMethod);
        method.append(userMgrInterface);

        auto reply = bus.call(method);
        reply.read(properties);
    }
    catch (const sdbusplus::exception_t& e)
    {
        lg2::debug("Failed to excute {METHOD}, path: {PATH}", "METHOD",
                   getAllPropertiesMethod, "PATH", userMgrObjBasePath);
        return;
    }
    for (const auto& t : properties)
    {
        auto key = t.first;
        if (key == allPrivProperty)
        {
            availablePrivileges = std::get<std::vector<std::string>>(t.second);
        }
        else if (key == allGrpProperty)
        {
            availableGroups = std::get<std::vector<std::string>>(t.second);
        }
    }
    // TODO: Implement Supported Privilege & Groups verification logic
    return;
}

std::timespec UserAccess::getUpdatedFileTime()
{
    struct stat fileStat;
    if (stat(ipmiUserDataFile, &fileStat) != 0)
    {
        lg2::debug("Error in getting last updated time stamp");
        return std::timespec{0, 0};
    }
    return fileStat.st_mtim;
}

void UserAccess::getUserProperties(const DbusUserObjProperties& properties,
                                   std::vector<std::string>& usrGrps,
                                   std::string& usrPriv, bool& usrEnabled)
{
    for (const auto& t : properties)
    {
        std::string key = t.first;
        if (key == userPrivProperty)
        {
            usrPriv = std::get<std::string>(t.second);
        }
        else if (key == userGrpProperty)
        {
            usrGrps = std::get<std::vector<std::string>>(t.second);
        }
        else if (key == userEnabledProperty)
        {
            usrEnabled = std::get<bool>(t.second);
        }
    }
    return;
}

int UserAccess::getUserObjProperties(const DbusUserObjValue& userObjs,
                                     std::vector<std::string>& usrGrps,
                                     std::string& usrPriv, bool& usrEnabled)
{
    auto usrObj = userObjs.find(usersInterface);
    if (usrObj != userObjs.end())
    {
        getUserProperties(usrObj->second, usrGrps, usrPriv, usrEnabled);
        return 0;
    }
    return -EIO;
}

void UserAccess::cacheUserDataFile()
{
    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        userLock{*userMutex};
    try
    {
        readUserData();
    }
    catch (const std::ios_base::failure& e)
    { // File is empty, create it for the first time
        std::fill(reinterpret_cast<uint8_t*>(&usersTbl),
                  reinterpret_cast<uint8_t*>(&usersTbl) + sizeof(usersTbl), 0);
        // user index 0 is reserved, starts with 1
        for (size_t userIndex = 1; userIndex <= ipmiMaxUsers; ++userIndex)
        {
            for (size_t chIndex = 0; chIndex < ipmiMaxChannels; ++chIndex)
            {
                usersTbl.user[userIndex].userPrivAccess[chIndex].privilege =
                    privNoAccess;
                usersTbl.user[userIndex]
                    .payloadAccess[chIndex]
                    .stdPayloadEnables1[static_cast<uint8_t>(
                        ipmi::PayloadType::SOL)] = true;
            }
        }
        writeUserData();
    }
    // Create lock file if it does not exist
    int fd = open(ipmiUserSignalLockFile, O_CREAT | O_TRUNC | O_SYNC,
                  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0)
    {
        lg2::error("Error in creating IPMI user signal lock file");
        throw std::ios_base::failure(
            "Error in creating temporary IPMI user signal lock file");
    }
    close(fd);

    sigHndlrLock = boost::interprocess::file_lock(ipmiUserSignalLockFile);
    // Register it for single object and single process either netipmid /
    // host-ipmid
    if (userUpdatedSignal == nullptr && sigHndlrLock.try_lock())
    {
        lg2::debug("Registering signal handler");
        userUpdatedSignal = std::make_unique<sdbusplus::bus::match_t>(
            bus,
            sdbusplus::bus::match::rules::type::signal() +
                sdbusplus::bus::match::rules::interface(dBusObjManager) +
                sdbusplus::bus::match::rules::path(userMgrObjBasePath),
            [&](sdbusplus::message_t& msg) {
                userUpdatedSignalHandler(*this, msg);
            });
        userMgrRenamedSignal = std::make_unique<sdbusplus::bus::match_t>(
            bus,
            sdbusplus::bus::match::rules::type::signal() +
                sdbusplus::bus::match::rules::interface(userMgrInterface) +
                sdbusplus::bus::match::rules::path(userMgrObjBasePath),
            [&](sdbusplus::message_t& msg) {
                userUpdatedSignalHandler(*this, msg);
            });
        userPropertiesSignal = std::make_unique<sdbusplus::bus::match_t>(
            bus,
            sdbusplus::bus::match::rules::type::signal() +
                sdbusplus::bus::match::rules::path_namespace(userObjBasePath) +
                sdbusplus::bus::match::rules::interface(
                    dBusPropertiesInterface) +
                sdbusplus::bus::match::rules::member(propertiesChangedSignal) +
                sdbusplus::bus::match::rules::argN(0, usersInterface),
            [&](sdbusplus::message_t& msg) {
                userUpdatedSignalHandler(*this, msg);
            });
        signalHndlrObject = true;
    }
    std::map<DbusUserObjPath, DbusUserObjValue> managedObjs;
    try
    {
        auto method =
            bus.new_method_call(userMgrService, userMgrObjBasePath,
                                dBusObjManager, getManagedObjectsMethod);
        auto reply = bus.call(method);
        reply.read(managedObjs);
    }
    catch (const sdbusplus::exception_t& e)
    {
        lg2::debug("Failed to excute {METHOD}, path: {PATH}", "METHOD",
                   getManagedObjectsMethod, "PATH", userMgrObjBasePath);
        return;
    }
    bool updateRequired = false;
    UsersTbl* userData = &usersTbl;
    // user index 0 is reserved, starts with 1
    for (size_t usrIdx = 1; usrIdx <= ipmiMaxUsers; ++usrIdx)
    {
        if ((userData->user[usrIdx].userInSystem) &&
            (userData->user[usrIdx].userName[0] != '\0'))
        {
            std::vector<std::string> usrGrps;
            std::string usrPriv;

            std::string userName(
                reinterpret_cast<char*>(userData->user[usrIdx].userName), 0,
                ipmiMaxUserName);
            sdbusplus::message::object_path tempUserPath(userObjBasePath);
            tempUserPath /= userName;
            std::string usersPath(tempUserPath);

            auto usrObj = managedObjs.find(usersPath);
            if (usrObj != managedObjs.end())
            {
                bool usrEnabled = false;

                // User exist. Lets check and update other fileds
                getUserObjProperties(usrObj->second, usrGrps, usrPriv,
                                     usrEnabled);
                if (std::find(usrGrps.begin(), usrGrps.end(), ipmiGrpName) ==
                    usrGrps.end())
                {
                    updateRequired = true;
                    // Group "ipmi" is removed so lets remove user in IPMI
                    deleteUserIndex(usrIdx);
                }
                else
                {
                    // Group "ipmi" is present so lets update other properties
                    // in IPMI
                    uint8_t priv = UserAccess::convertToIPMIPrivilege(usrPriv) &
                                   privMask;
                    // Update all channels priv, only if it is not equivalent to
                    // getUsrMgmtSyncIndex()
                    if (userData->user[usrIdx]
                            .userPrivAccess[getUsrMgmtSyncIndex()]
                            .privilege != priv)
                    {
                        updateRequired = true;
                        for (size_t chIndex = 0; chIndex < ipmiMaxChannels;
                             ++chIndex)
                        {
                            userData->user[usrIdx]
                                .userPrivAccess[chIndex]
                                .privilege = priv;
                        }
                    }
                    if (userData->user[usrIdx].userEnabled != usrEnabled)
                    {
                        updateRequired = true;
                        userData->user[usrIdx].userEnabled = usrEnabled;
                    }
                }

                // We are done with this obj. lets delete from MAP
                managedObjs.erase(usrObj);
            }
            else
            {
                updateRequired = true;
                deleteUserIndex(usrIdx);
            }
        }
    }

    // Walk through remnaining managedObj users list
    // Add them to ipmi data base
    for (const auto& usrObj : managedObjs)
    {
        std::vector<std::string> usrGrps;
        std::string usrPriv, userName;
        bool usrEnabled = false;
        std::string usrObjPath = std::string(usrObj.first);
        if (getUserNameFromPath(usrObj.first.str, userName) != 0)
        {
            lg2::error("Error in user object path");
            continue;
        }
        getUserObjProperties(usrObj.second, usrGrps, usrPriv, usrEnabled);
        // Add 'ipmi' group users
        if (std::find(usrGrps.begin(), usrGrps.end(), ipmiGrpName) !=
            usrGrps.end())
        {
            updateRequired = true;
            // CREATE NEW USER
            if (true != addUserEntry(userName, usrPriv, usrEnabled))
            {
                break;
            }
        }
    }

    if (updateRequired)
    {
        // All userData slots update done. Lets write the data
        writeUserData();
    }

    return;
}
} // namespace ipmi
