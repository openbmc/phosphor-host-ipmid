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

#include "apphandler.hpp"

#include <security/pam_appl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <boost/interprocess/sync/named_recursive_mutex.hpp>
#include <boost/interprocess/sync/scoped_lock.hpp>
#include <cerrno>
#include <fstream>
#include <nlohmann/json.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <regex>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/server/object.hpp>
#include <variant>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/User/Common/error.hpp>

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

// Object Mapper related
static constexpr const char* objMapperService =
    "xyz.openbmc_project.ObjectMapper";
static constexpr const char* objMapperPath =
    "/xyz/openbmc_project/object_mapper";
static constexpr const char* objMapperInterface =
    "xyz.openbmc_project.ObjectMapper";
static constexpr const char* getSubTreeMethod = "GetSubTree";
static constexpr const char* getObjectMethod = "GetObject";

static constexpr const char* ipmiUserMutex = "ipmi_usr_mutex";
static constexpr const char* ipmiMutexCleanupLockFile =
    "/var/lib/ipmi/ipmi_usr_mutex_cleanup";
static constexpr const char* ipmiUserDataFile = "/var/lib/ipmi/ipmi_user.json";
static constexpr const char* ipmiGrpName = "ipmi";
static constexpr size_t privNoAccess = 0xF;
static constexpr size_t privMask = 0xF;

// User manager related
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
    sdbusplus::xyz::openbmc_project::User::Common::Error::NoResource;

using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

std::unique_ptr<sdbusplus::bus::match_t> userUpdatedSignal
    __attribute__((init_priority(101)));
std::unique_ptr<sdbusplus::bus::match_t> userMgrRenamedSignal
    __attribute__((init_priority(101)));
std::unique_ptr<sdbusplus::bus::match_t> userPropertiesSignal
    __attribute__((init_priority(101)));

// TODO:  Below code can be removed once it is moved to common layer libmiscutil
std::string getUserService(sdbusplus::bus::bus& bus, const std::string& intf,
                           const std::string& path)
{
    auto mapperCall = bus.new_method_call(objMapperService, objMapperPath,
                                          objMapperInterface, getObjectMethod);

    mapperCall.append(path);
    mapperCall.append(std::vector<std::string>({intf}));

    auto mapperResponseMsg = bus.call(mapperCall);

    std::map<std::string, std::vector<std::string>> mapperResponse;
    mapperResponseMsg.read(mapperResponse);

    if (mapperResponse.begin() == mapperResponse.end())
    {
        throw sdbusplus::exception::SdBusError(
            -EIO, "ERROR in reading the mapper response");
    }

    return mapperResponse.begin()->first;
}

void setDbusProperty(sdbusplus::bus::bus& bus, const std::string& service,
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
    catch (const sdbusplus::exception::SdBusError& e)
    {
        log<level::ERR>("Failed to set property",
                        entry("PROPERTY=%s", property.c_str()),
                        entry("PATH=%s", objPath.c_str()),
                        entry("INTERFACE=%s", interface.c_str()));
        throw;
    }
}

static std::string getUserServiceName()
{
    static sdbusplus::bus::bus bus(ipmid_get_sd_bus_connection());
    static std::string userMgmtService;
    if (userMgmtService.empty())
    {
        try
        {
            userMgmtService =
                ipmi::getUserService(bus, userMgrInterface, userMgrObjBasePath);
        }
        catch (const sdbusplus::exception::SdBusError& e)
        {
            userMgmtService.clear();
        }
    }
    return userMgmtService;
}

UserAccess& getUserAccessObject()
{
    static UserAccess userAccess;
    return userAccess;
}

int getUserNameFromPath(const std::string& path, std::string& userName)
{
    static size_t pos = strlen(userObjBasePath) + 1;
    if (path.find(userObjBasePath) == std::string::npos)
    {
        return -EINVAL;
    }
    userName.assign(path, pos, path.size());
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
            log<level::DEBUG>("User not found for signal",
                              entry("USER_NAME=%s", userName.c_str()),
                              entry("USER_EVENT=%d", userEvent));
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
                log<level::ERR>("Unhandled user event",
                                entry("USER_EVENT=%d", userEvent));
                return;
            }
        }
    }
    usrAccess.writeUserData();
    log<level::DEBUG>("User event handled successfully",
                      entry("USER_NAME=%s", userName.c_str()),
                      entry("USER_EVENT=%d", userEvent));

    return;
}

void userUpdatedSignalHandler(UserAccess& usrAccess,
                              sdbusplus::message::message& msg)
{
    static sdbusplus::bus::bus bus(ipmid_get_sd_bus_connection());
    std::string signal = msg.get_member();
    std::string userName, update, priv, newUserName;
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
        log<level::ERR>("Unknown user update signal",
                        entry("SIGNAL=%s", signal.c_str()));
        return;
    }

    if (signal.empty() || userName.empty() ||
        (signal == userRenamedSignal && newUserName.empty()))
    {
        log<level::ERR>("Invalid inputs received");
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
                            getUserServiceName().c_str(), msg.get_path(),
                            dBusPropertiesInterface, getAllPropertiesMethod);
                        method.append(usersInterface);
                        auto reply = bus.call(method);
                        reply.read(properties);
                    }
                    catch (const sdbusplus::exception::SdBusError& e)
                    {
                        log<level::DEBUG>(
                            "Failed to excute method",
                            entry("METHOD=%s", getAllPropertiesMethod),
                            entry("PATH=%s", msg.get_path()));
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
        log<level::DEBUG>("Unable to open mutex cleanup file");
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

    initUserDataFile();
    getSystemPrivAndGroups();
    sigHndlrLock = boost::interprocess::file_lock(ipmiUserDataFile);
    // Register it for single object and single process either netipimd /
    // host-ipmid
    if (userUpdatedSignal == nullptr && sigHndlrLock.try_lock())
    {
        log<level::DEBUG>("Registering signal handler");
        userUpdatedSignal = std::make_unique<sdbusplus::bus::match_t>(
            bus,
            sdbusplus::bus::match::rules::type::signal() +
                sdbusplus::bus::match::rules::interface(dBusObjManager) +
                sdbusplus::bus::match::rules::path(userMgrObjBasePath),
            [&](sdbusplus::message::message& msg) {
                userUpdatedSignalHandler(*this, msg);
            });
        userMgrRenamedSignal = std::make_unique<sdbusplus::bus::match_t>(
            bus,
            sdbusplus::bus::match::rules::type::signal() +
                sdbusplus::bus::match::rules::interface(userMgrInterface) +
                sdbusplus::bus::match::rules::path(userMgrObjBasePath),
            [&](sdbusplus::message::message& msg) {
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
            [&](sdbusplus::message::message& msg) {
                userUpdatedSignalHandler(*this, msg);
            });
        signalHndlrObject = true;
    }
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
    return ((priv >= PRIVILEGE_CALLBACK && priv <= PRIVILEGE_OEM) ||
            priv == privNoAccess);
}

uint8_t UserAccess::getUsrMgmtSyncIndex()
{
    // TODO: Need to get LAN1 channel number dynamically,
    // which has to be in sync with system user privilege
    // level(Phosphor-user-manager). Note: For time being chanLan1 is marked as
    // sync index to the user-manager privilege..
    return static_cast<uint8_t>(EChannelID::chanLan1);
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
        log<level::ERR>("Error in converting to IPMI privilege",
                        entry("PRIV=%s", value.c_str()));
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
        log<level::ERR>("Error in converting to system privilege",
                        entry("PRIV=%d", static_cast<uint8_t>(value)));
        throw std::out_of_range("Out of range - convertToSystemPrivilege");
    }
}

bool UserAccess::isValidUserName(const char* userNameInChar)
{
    if (!userNameInChar)
    {
        log<level::ERR>("null ptr");
        return false;
    }
    std::string userName(userNameInChar, 0, ipmiMaxUserName);
    if (!std::regex_match(userName.c_str(),
                          std::regex("[a-zA-z_][a-zA-Z_0-9]*")))
    {
        log<level::ERR>("Unsupported characters in user name");
        return false;
    }
    if (userName == "root")
    {
        log<level::ERR>("Invalid user name - root");
        return false;
    }
    std::map<DbusUserObjPath, DbusUserObjValue> properties;
    try
    {
        auto method = bus.new_method_call(getUserServiceName().c_str(),
                                          userMgrObjBasePath, dBusObjManager,
                                          getManagedObjectsMethod);
        auto reply = bus.call(method);
        reply.read(properties);
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        log<level::ERR>("Failed to excute method",
                        entry("METHOD=%s", getSubTreeMethod),
                        entry("PATH=%s", userMgrObjBasePath));
        return false;
    }

    std::string usersPath = std::string(userObjBasePath) + "/" + userName;
    if (properties.find(usersPath) != properties.end())
    {
        log<level::DEBUG>("User name already exists",
                          entry("USER_NAME=%s", userName.c_str()));
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
        return PAM_AUTH_ERR;
    }
    size_t passSize = std::strlen(reinterpret_cast<char*>(appdataPtr)) + 1;
    char* pass = reinterpret_cast<char*>(malloc(passSize));
    std::strncpy(pass, reinterpret_cast<char*>(appdataPtr), passSize);

    *resp = reinterpret_cast<pam_response*>(
        calloc(numMsg, sizeof(struct pam_response)));

    for (int i = 0; i < numMsg; ++i)
    {
        if (msg[i]->msg_style != PAM_PROMPT_ECHO_OFF)
        {
            continue;
        }
        resp[i]->resp = pass;
    }
    return PAM_SUCCESS;
}

/** @brief Updating the PAM password
 *
 *  @param[in] username - username in string
 *
 *  @param[in] password  - new password in string
 *
 *  @return status
 */

bool pamUpdatePasswd(const char* username, const char* password)
{
    const struct pam_conv localConversation = {pamFunctionConversation,
                                               const_cast<char*>(password)};
    pam_handle_t* localAuthHandle = NULL; // this gets set by pam_start

    if (pam_start("passwd", username, &localConversation, &localAuthHandle) !=
        PAM_SUCCESS)
    {
        return false;
    }
    int retval = pam_chauthtok(localAuthHandle, PAM_SILENT);

    if (retval != PAM_SUCCESS)
    {
        if (retval == PAM_AUTHTOK_ERR)
        {
            log<level::DEBUG>("Authentication Failure");
        }
        else
        {
            log<level::DEBUG>("pam_chauthtok returned failure",
                              entry("ERROR=%d", retval));
        }
        pam_end(localAuthHandle, retval);
        return false;
    }
    if (pam_end(localAuthHandle, PAM_SUCCESS) != PAM_SUCCESS)
    {
        return false;
    }
    return true;
}

bool pamUserCheckAuthenticate(std::string_view username,
                              std::string_view password)
{
    const struct pam_conv localConversation = {
        pamFunctionConversation, const_cast<char*>(password.data())};

    pam_handle_t* localAuthHandle = NULL; // this gets set by pam_start

    if (pam_start("dropbear", username.data(), &localConversation,
                  &localAuthHandle) != PAM_SUCCESS)
    {
        log<level::ERR>("User Authentication Failure");
        return false;
    }

    int retval = pam_authenticate(localAuthHandle,
                                  PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK);

    if (retval != PAM_SUCCESS)
    {
        log<level::DEBUG>("pam_authenticate returned failure",
                          entry("ERROR=%d", retval));

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

ipmi_ret_t UserAccess::setSpecialUserPassword(const std::string& userName,
                                              const std::string& userPassword)
{
    if (!pamUpdatePasswd(userName.c_str(), userPassword.c_str()))
    {
        log<level::DEBUG>("Failed to update password");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    return IPMI_CC_OK;
}

ipmi_ret_t UserAccess::setUserPassword(const uint8_t userId,
                                       const char* userPassword)
{
    std::string userName;
    if (ipmiUserGetUserName(userId, userName) != IPMI_CC_OK)
    {
        log<level::DEBUG>("User Name not found",
                          entry("USER-ID:%d", (uint8_t)userId));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }
    std::string passwd;
    passwd.assign(reinterpret_cast<const char*>(userPassword), 0,
                  maxIpmi20PasswordSize);
    if (!std::regex_match(passwd.c_str(),
                          std::regex("[a-zA-z_0-9][a-zA-Z_0-9,?:`!\"]*")))
    {
        log<level::DEBUG>("Invalid password fields",
                          entry("USER-ID:%d", (uint8_t)userId));
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    if (!pamUpdatePasswd(userName.c_str(), passwd.c_str()))
    {
        log<level::DEBUG>("Failed to update password",
                          entry("USER-ID:%d", (uint8_t)userId));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    return IPMI_CC_OK;
}

ipmi_ret_t UserAccess::setUserEnabledState(const uint8_t userId,
                                           const bool& enabledState)
{
    if (!isValidUserId(userId))
    {
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }
    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        userLock{*userMutex};
    UserInfo* userInfo = getUserInfo(userId);
    std::string userName;
    userName.assign(reinterpret_cast<char*>(userInfo->userName), 0,
                    ipmiMaxUserName);
    if (userName.empty())
    {
        log<level::DEBUG>("User name not set / invalid");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    if (userInfo->userEnabled != enabledState)
    {
        std::string userPath = std::string(userObjBasePath) + "/" + userName;
        setDbusProperty(bus, getUserServiceName(), userPath, usersInterface,
                        userEnabledProperty, enabledState);
        userInfo->userEnabled = enabledState;
        try
        {
            writeUserData();
        }
        catch (const std::exception& e)
        {
            log<level::DEBUG>("Write user data failed");
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
    }
    return IPMI_CC_OK;
}

ipmi_ret_t UserAccess::setUserPrivilegeAccess(const uint8_t userId,
                                              const uint8_t chNum,
                                              const UserPrivAccess& privAccess,
                                              const bool& otherPrivUpdates)
{
    if (!isValidChannel(chNum))
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    if (!isValidUserId(userId))
    {
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }
    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        userLock{*userMutex};
    UserInfo* userInfo = getUserInfo(userId);
    std::string userName;
    userName.assign(reinterpret_cast<char*>(userInfo->userName), 0,
                    ipmiMaxUserName);
    if (userName.empty())
    {
        log<level::DEBUG>("User name not set / invalid");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    std::string priv = convertToSystemPrivilege(
        static_cast<CommandPrivilege>(privAccess.privilege));
    uint8_t syncIndex = getUsrMgmtSyncIndex();
    if (chNum == syncIndex &&
        privAccess.privilege != userInfo->userPrivAccess[syncIndex].privilege)
    {
        std::string userPath = std::string(userObjBasePath) + "/" + userName;
        setDbusProperty(bus, getUserServiceName(), userPath, usersInterface,
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
        log<level::DEBUG>("Write user data failed");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    return IPMI_CC_OK;
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
        log<level::DEBUG>("User not found",
                          entry("USER_NAME=%s", userName.c_str()));
        return invalidUserId;
    }

    return usrIndex;
}

ipmi_ret_t UserAccess::getUserName(const uint8_t userId, std::string& userName)
{
    if (!isValidUserId(userId))
    {
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }
    UserInfo* userInfo = getUserInfo(userId);
    userName.assign(reinterpret_cast<char*>(userInfo->userName), 0,
                    ipmiMaxUserName);
    return IPMI_CC_OK;
}

ipmi_ret_t UserAccess::setUserName(const uint8_t userId,
                                   const char* userNameInChar)
{
    if (!isValidUserId(userId))
    {
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        userLock{*userMutex};
    std::string oldUser;
    getUserName(userId, oldUser);

    std::string newUser(userNameInChar, 0, ipmiMaxUserName);
    if (oldUser == newUser)
    {
        // requesting to set the same user name, return success.
        return IPMI_CC_OK;
    }
    bool validUser = isValidUserName(userNameInChar);
    UserInfo* userInfo = getUserInfo(userId);
    if (newUser.empty() && !oldUser.empty())
    {
        // Delete existing user
        std::string userPath = std::string(userObjBasePath) + "/" + oldUser;
        try
        {
            auto method = bus.new_method_call(
                getUserServiceName().c_str(), userPath.c_str(),
                deleteUserInterface, deleteUserMethod);
            auto reply = bus.call(method);
        }
        catch (const sdbusplus::exception::SdBusError& e)
        {
            log<level::DEBUG>("Failed to excute method",
                              entry("METHOD=%s", deleteUserMethod),
                              entry("PATH=%s", userPath.c_str()));
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
        deleteUserIndex(userId);
    }
    else if (oldUser.empty() && !newUser.empty() && validUser)
    {
        try
        {
            // Create new user
            auto method = bus.new_method_call(
                getUserServiceName().c_str(), userMgrObjBasePath,
                userMgrInterface, createUserMethod);
            method.append(newUser.c_str(), availableGroups, "", false);
            auto reply = bus.call(method);
        }
        catch (const sdbusplus::exception::SdBusError& e)
        {
            log<level::DEBUG>("Failed to excute method",
                              entry("METHOD=%s", createUserMethod),
                              entry("PATH=%s", userMgrObjBasePath));
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
        std::memcpy(userInfo->userName, userNameInChar, ipmiMaxUserName);
        userInfo->userInSystem = true;
    }
    else if (oldUser != newUser && validUser)
    {
        try
        {
            // User rename
            auto method = bus.new_method_call(
                getUserServiceName().c_str(), userMgrObjBasePath,
                userMgrInterface, renameUserMethod);
            method.append(oldUser.c_str(), newUser.c_str());
            auto reply = bus.call(method);
        }
        catch (const sdbusplus::exception::SdBusError& e)
        {
            log<level::DEBUG>("Failed to excute method",
                              entry("METHOD=%s", renameUserMethod),
                              entry("PATH=%s", userMgrObjBasePath));
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
        std::fill(static_cast<uint8_t*>(userInfo->userName),
                  static_cast<uint8_t*>(userInfo->userName) +
                      sizeof(userInfo->userName),
                  0);
        std::memcpy(userInfo->userName, userNameInChar, ipmiMaxUserName);
        ipmiRenameUserEntryPassword(oldUser, newUser);
        userInfo->userInSystem = true;
    }
    else if (!validUser)
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    try
    {
        writeUserData();
    }
    catch (const std::exception& e)
    {
        log<level::DEBUG>("Write user data failed");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    return IPMI_CC_OK;
}

static constexpr const char* jsonUserName = "user_name";
static constexpr const char* jsonPriv = "privilege";
static constexpr const char* jsonIpmiEnabled = "ipmi_enabled";
static constexpr const char* jsonLinkAuthEnabled = "link_auth_enabled";
static constexpr const char* jsonAccCallbk = "access_callback";
static constexpr const char* jsonUserEnabled = "user_enabled";
static constexpr const char* jsonUserInSys = "user_in_system";
static constexpr const char* jsonFixedUser = "fixed_user_name";

void UserAccess::readUserData()
{
    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        userLock{*userMutex};

    std::ifstream iUsrData(ipmiUserDataFile, std::ios::in | std::ios::binary);
    if (!iUsrData.good())
    {
        log<level::ERR>("Error in reading IPMI user data file");
        throw std::ios_base::failure("Error opening IPMI user data file");
    }

    Json jsonUsersTbl = Json::array();
    jsonUsersTbl = Json::parse(iUsrData, nullptr, false);

    if (jsonUsersTbl.size() != ipmiMaxUsers)
    {
        log<level::ERR>(
            "Error in reading IPMI user data file - User count issues");
        throw std::runtime_error(
            "Corrupted IPMI user data file - invalid user count");
    }
    // user index 0 is reserved, starts with 1
    for (size_t usrIndex = 1; usrIndex <= ipmiMaxUsers; ++usrIndex)
    {
        Json userInfo = jsonUsersTbl[usrIndex - 1]; // json array starts with 0.
        if (userInfo.is_null())
        {
            log<level::ERR>("Error in reading IPMI user data file - "
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
        if (privilege.size() != ipmiMaxChannels ||
            ipmiEnabled.size() != ipmiMaxChannels ||
            linkAuthEnabled.size() != ipmiMaxChannels ||
            accessCallback.size() != ipmiMaxChannels)
        {
            log<level::ERR>("Error in reading IPMI user data file - "
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
        usersTbl.user[usrIndex].userEnabled =
            userInfo[jsonUserEnabled].get<bool>();
        usersTbl.user[usrIndex].userInSystem =
            userInfo[jsonUserInSys].get<bool>();
        usersTbl.user[usrIndex].fixedUserName =
            userInfo[jsonFixedUser].get<bool>();
    }

    log<level::DEBUG>("User data read from IPMI data file");
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
        jsonUsersTbl.push_back(jsonUserInfo);
    }

    static std::string tmpFile{std::string(ipmiUserDataFile) + "_tmp"};
    int fd = open(tmpFile.c_str(), O_CREAT | O_WRONLY | O_TRUNC | O_SYNC,
                  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0)
    {
        log<level::ERR>("Error in creating temporary IPMI user data file");
        throw std::ios_base::failure(
            "Error in creating temporary IPMI user data file");
    }
    const auto& writeStr = jsonUsersTbl.dump();
    if (write(fd, writeStr.c_str(), writeStr.size()) !=
        static_cast<ssize_t>(writeStr.size()))
    {
        close(fd);
        log<level::ERR>("Error in writing temporary IPMI user data file");
        throw std::ios_base::failure(
            "Error in writing temporary IPMI user data file");
    }
    close(fd);

    if (std::rename(tmpFile.c_str(), ipmiUserDataFile) != 0)
    {
        log<level::ERR>("Error in renaming temporary IPMI user data file");
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
            log<level::DEBUG>("User name exists",
                              entry("USER_NAME=%s", userName.c_str()));
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
        log<level::ERR>("No empty slots found");
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
    std::time_t updateTime = getUpdatedFileTime();
    if (updateTime != fileLastUpdatedTime || updateTime == -EIO)
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
        auto method = bus.new_method_call(
            getUserServiceName().c_str(), userMgrObjBasePath,
            dBusPropertiesInterface, getAllPropertiesMethod);
        method.append(userMgrInterface);

        auto reply = bus.call(method);
        reply.read(properties);
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        log<level::DEBUG>("Failed to excute method",
                          entry("METHOD=%s", getAllPropertiesMethod),
                          entry("PATH=%s", userMgrObjBasePath));
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

std::time_t UserAccess::getUpdatedFileTime()
{
    struct stat fileStat;
    if (stat(ipmiUserDataFile, &fileStat) != 0)
    {
        log<level::DEBUG>("Error in getting last updated time stamp");
        return -EIO;
    }
    return fileStat.st_mtime;
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

void UserAccess::initUserDataFile()
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
            }
        }
        writeUserData();
    }
    std::map<DbusUserObjPath, DbusUserObjValue> managedObjs;
    try
    {
        auto method = bus.new_method_call(getUserServiceName().c_str(),
                                          userMgrObjBasePath, dBusObjManager,
                                          getManagedObjectsMethod);
        auto reply = bus.call(method);
        reply.read(managedObjs);
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        log<level::DEBUG>("Failed to excute method",
                          entry("METHOD=%s", getSubTreeMethod),
                          entry("PATH=%s", userMgrObjBasePath));
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
            bool usrEnabled;

            std::string userName(
                reinterpret_cast<char*>(userData->user[usrIdx].userName), 0,
                ipmiMaxUserName);
            std::string usersPath =
                std::string(userObjBasePath) + "/" + userName;

            auto usrObj = managedObjs.find(usersPath);
            if (usrObj != managedObjs.end())
            {
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
                    uint8_t priv =
                        UserAccess::convertToIPMIPrivilege(usrPriv) & privMask;
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
        bool usrEnabled;
        std::string usrObjPath = std::string(usrObj.first);
        if (getUserNameFromPath(usrObj.first.str, userName) != 0)
        {
            log<level::ERR>("Error in user object path");
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
