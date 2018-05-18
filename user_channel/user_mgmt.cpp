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
#include <phosphor-ipmi-host/apphandler.h>
#include <sys/stat.h>
#include <unistd.h>
#include <host-ipmid/ipmid-host-cmd.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/server/object.hpp>
#include <variantvisitors.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/User/Common/error.hpp>
#include <fstream>
#include <regex>
#include <boost/interprocess/sync/named_recursive_mutex.hpp>
#include <boost/interprocess/sync/scoped_lock.hpp>

using namespace phosphor::logging;

namespace ipmi
{

// TODO: Move D-Bus & Object Manager related stuff, to common files
// D-Bus property related
static constexpr char DBUS_PROPERTIES_INTERFACE[] =
    "org.freedesktop.DBus.Properties";
static constexpr char DBUS_PROPERTIES_GET_ALL_METHOD[] = "GetAll";
static constexpr char DBUS_PROPERTIES_CHANGED_SIGNAL[] = "PropertiesChanged";

// Object Manager related
static constexpr char DBUS_OBJ_MANAGER_INTERFACE[] =
    "org.freedesktop.DBus.ObjectManager";
static constexpr char DBUS_OBJ_MANAGER_GET_OBJ_METHOD[] = "GetManagedObjects";
// Object Manager signals
static constexpr char INTF_ADDED_SIGNAL[] = "InterfacesAdded";
static constexpr char INTF_REMOVED_SIGNAL[] = "InterfacesRemoved";

// Object Mapper related
static constexpr char OBJ_MAPPER_SERVICE[] = "xyz.openbmc_project.ObjectMapper";
static constexpr char OBJ_MAPPER_OBJ_PATH[] =
    "/xyz/openbmc_project/object_mapper";
static constexpr char OBJ_MAPPER_INTERFACE[] =
    "xyz.openbmc_project.ObjectMapper";
static constexpr char OBJ_MAPPER_GET_SUBTREE_METHOD[] = "GetSubTree";
static constexpr char OBJ_MAPPER_GET_OBJECT_METHOD[] = "GetObject";

static constexpr char IPMI_USER_DATA_FILE[] = "/var/ipmi_user.dat";
static constexpr char IPMI_GRP_NAME[] = "ipmi";
static constexpr size_t PRIVILEGE_NO_ACCESS = 0xF;
static constexpr size_t PRIVILEGE_MASK = 0xF;

// User manager related
static constexpr char USER_MANAGER_OBJ_BASE_PATH[] =
    "/xyz/openbmc_project/user";
static constexpr char USER_MANAGER_OBJ_USERS_BASE_PATH[] =
    "/xyz/openbmc_project/user/Users";
static constexpr char USER_MANAGER_MGR_INTERFACE[] =
    "xyz.openbmc_project.User.Mgr";
static constexpr char USER_MANAGER_USER_INTERFACE[] =
    "xyz.openbmc_project.User.Users";

static constexpr char CREATE_USER_METHOD[] = "CreateUser";
static constexpr char DELETE_USER_METHOD[] = "DeleteUser";
static constexpr char RENAME_USER_METHOD[] = "RenameUser";
// User manager signal memebers
static constexpr char USER_RENAMED_SIGNAL[] = "UserRenamed";
// Mgr interface properties
static constexpr char MGR_ALL_PRIV_PROP[] = "AllPrivileges";
static constexpr char MGR_ALL_GRPS_PROP[] = "AllGroups";
// User interface properties
static constexpr char USER_PRIV_PROP[] = "UserPrivilege";
static constexpr char USER_GROUP_PROP[] = "UserGroups";
static constexpr char USER_ENABLED_PROP[] = "UserEnabled";

static std::array<std::string, (PRIVILEGE_OEM + 1)> ipmiPrivIndex = {
    "",              // PRIVILEGE_RESERVED - 0
    "priv-callback", // PRIVILEGE_CALLBACK - 1
    "priv-user",     // PRIVILEGE_USER - 2
    "priv-operator", // PRIVILEGE_OPERATOR - 3
    "priv-admin",    // PRIVILEGE_ADMIN - 4
    "priv-custom"    // PRIVILEGE_OEM - 5
};

using PrivAndGroupType =
    sdbusplus::message::variant<std::string, std::vector<std::string>>;

using NoResource =
    sdbusplus::xyz::openbmc_project::User::Common::Error::NoResource;

using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

std::unique_ptr<sdbusplus::bus::match_t> userUpdatedSignal(nullptr);
std::unique_ptr<sdbusplus::bus::match_t> userPropertiesSignal(nullptr);

// TODO: Netipmid doesn't support getService. Below code can be removed
// once netipmid supports / lib utils has been added.
std::string getUserService(sdbusplus::bus::bus &bus, const std::string &intf,
                           const std::string &path)
{
    auto mapperCall =
        bus.new_method_call(OBJ_MAPPER_SERVICE, OBJ_MAPPER_OBJ_PATH,
                            OBJ_MAPPER_INTERFACE, OBJ_MAPPER_GET_OBJECT_METHOD);

    mapperCall.append(path);
    mapperCall.append(std::vector<std::string>({intf}));

    auto mapperResponseMsg = bus.call(mapperCall);

    if (mapperResponseMsg.is_method_error())
    {
        throw std::runtime_error("ERROR in mapper call");
    }

    std::map<std::string, std::vector<std::string>> mapperResponse;
    mapperResponseMsg.read(mapperResponse);

    if (mapperResponse.begin() == mapperResponse.end())
    {
        throw std::runtime_error("ERROR in reading the mapper response");
    }

    return mapperResponse.begin()->first;
}

static sdbusplus::bus::bus bus(ipmid_get_sd_bus_connection());
static std::string userMgmtService = ipmi::getUserService(
    bus, USER_MANAGER_MGR_INTERFACE, USER_MANAGER_OBJ_BASE_PATH);

static UserAccess userAccess;

UserAccess &getUserAccessObject()
{
    return userAccess;
}

int getUserNameFromPath(const std::string &path, std::string &userName)
{
    static size_t pos = strlen(USER_MANAGER_OBJ_USERS_BASE_PATH) + 1;
    if (path.find(USER_MANAGER_OBJ_USERS_BASE_PATH) == std::string::npos)
    {
        return -1;
    }
    userName.assign(path, pos, path.size());
    return 0;
}

void userUpdateHelper(UserAccess *usrAccess, const UserUpdateEvent &userEvent,
                      const std::string &userName, const std::string &priv,
                      const bool &enabled, const std::string &newUserName)
{
    if (usrAccess == nullptr)
    {
        log<level::DEBUG>("Null user access pointer - Invalid input");
        return;
    }
    userdata_t *userData = usrAccess->getUserDataPtr();
    if (userEvent == USER_CREATED)
    {
        if (usrAccess->addUserEntry(userName, priv, enabled) == false)
        {
            return;
        }
    }
    else
    {
        size_t usrIndex = 1;
        for (; usrIndex <= IPMI_MAX_USERS; ++usrIndex)
        {
            std::string curName((char *)userData->user[usrIndex].userName, 0,
                                IPMI_MAX_USER_NAME);
            if (userName == curName)
            {
                break; // found the entry
            }
        }
        if (usrIndex > IPMI_MAX_USERS)
        {
            log<level::DEBUG>("User not found for signal",
                              entry("USER_NAME=%s", userName.c_str()),
                              entry("USER_EVENT=%d", userEvent));
            return;
        }
        switch (userEvent)
        {
            case USER_DELETED:
            {
                usrAccess->deleteUserIndex(usrIndex);
                break;
            }
            case USER_PRIV_UPDATED:
            {
                uint8_t userPriv =
                    UserAccess::convertToIPMIPrivilege(priv) & PRIVILEGE_MASK;
                for (size_t chIndex = 0; chIndex < IPMI_MAX_CHANNELS; ++chIndex)
                {
                    userData->user[usrIndex].userPrivAccess[chIndex].privilege =
                        userPriv;
                }
                break;
            }
            case USER_RENAMED:
            {
                std::fill((uint8_t *)userData->user[usrIndex].userName,
                          (uint8_t *)userData->user[usrIndex].userName +
                              sizeof(userData->user[usrIndex].userName),
                          0);
                std::strncpy((char *)userData->user[usrIndex].userName,
                             newUserName.c_str(), IPMI_MAX_USER_NAME);
                // TODO: Api call to update ipmi password store
                break;
            }
            case USER_STATE_UPDATED:
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
    usrAccess->writeUserData();
    log<level::DEBUG>("User event handled successfully",
                      entry("USER_NAME=%s", userName.c_str()),
                      entry("USER_EVENT=%d", userEvent));

    return;
}

void userUpdatedSignalHandler(UserAccess *usrAccess,
                              sdbusplus::message::message &msg)
{
    std::string signal = msg.get_member();
    std::string userName, update, priv, newUserName;
    std::vector<std::string> groups;
    bool enabled = false;
    UserUpdateEvent userEvent = RESERVED_EVENT;
    if (signal == INTF_ADDED_SIGNAL)
    {
        DbusUserObjPath objPath;
        DbusUserObjValue objValue;
        msg.read(objPath, objValue);
        getUserNameFromPath(objPath.str, userName);
        if (usrAccess->getUserObjProperties(objValue, groups, priv, enabled) !=
            0)
        {
            return;
        }
        if (std::find(groups.begin(), groups.end(), IPMI_GRP_NAME) ==
            groups.end())
        {
            return;
        }
        userEvent = USER_CREATED;
    }
    else if (signal == INTF_REMOVED_SIGNAL)
    {
        DbusUserObjPath objPath;
        std::vector<std::string> interfaces;
        msg.read(objPath, interfaces);
        getUserNameFromPath(objPath.str, userName);
        userEvent = USER_DELETED;
    }
    else if (signal == USER_RENAMED_SIGNAL)
    {
        msg.read(userName, newUserName);
        userEvent = USER_RENAMED;
    }
    else if (signal == DBUS_PROPERTIES_CHANGED_SIGNAL)
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
        (signal == USER_RENAMED_SIGNAL && newUserName.empty()))
    {
        log<level::ERR>("Invalid inputs received");
        return;
    }

    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        userLock{*(usrAccess->userMutex.get())};
    usrAccess->checkAndReloadUserData();

    if (signal == DBUS_PROPERTIES_CHANGED_SIGNAL)
    {
        std::string intfName;
        DbusUserObjProperties chProperties;
        msg.read(intfName, chProperties); // skip reading 3rd argument.
        for (const auto &prop : chProperties)
        {
            userEvent = RESERVED_EVENT;
            std::string member = prop.first;
            if (member == USER_PRIV_PROP)
            {
                priv = prop.second.get<std::string>();
                userEvent = USER_PRIV_UPDATED;
            }
            else if (member == USER_GROUP_PROP)
            {
                groups = prop.second.get<std::vector<std::string>>();
                userEvent = USER_GRP_UPDATED;
            }
            else if (member == USER_ENABLED_PROP)
            {
                enabled = prop.second.get<bool>();
                userEvent = USER_STATE_UPDATED;
            }
            // Process based on event type.
            if (userEvent == USER_GRP_UPDATED)
            {
                if (std::find(groups.begin(), groups.end(), IPMI_GRP_NAME) ==
                    groups.end())
                {
                    // remove user from ipmi user list.
                    userUpdateHelper(usrAccess, USER_DELETED, userName, priv,
                                     enabled, newUserName);
                }
                else
                {
                    auto method = bus.new_method_call(
                        userMgmtService.c_str(), msg.get_path(),
                        DBUS_PROPERTIES_INTERFACE,
                        DBUS_PROPERTIES_GET_ALL_METHOD);
                    method.append(USER_MANAGER_USER_INTERFACE);
                    auto reply = bus.call(method);
                    if (reply.is_method_error())
                    {
                        log<level::DEBUG>(
                            "Failed to excute method",
                            entry("METHOD=%s", DBUS_PROPERTIES_GET_ALL_METHOD),
                            entry("PATH=%s", msg.get_path()));
                        return;
                    }
                    DbusUserObjProperties properties;
                    reply.read(properties);
                    usrAccess->getUserProperties(properties, groups, priv,
                                                 enabled);
                    // add user to ipmi user list.
                    userUpdateHelper(usrAccess, USER_CREATED, userName, priv,
                                     enabled, newUserName);
                }
            }
            else if (userEvent != RESERVED_EVENT)
            {
                userUpdateHelper(usrAccess, userEvent, userName, priv, enabled,
                                 newUserName);
            }
        }
    }
    else if (userEvent != RESERVED_EVENT)
    {
        userUpdateHelper(usrAccess, userEvent, userName, priv, enabled,
                         newUserName);
    }
    return;
}

UserAccess::~UserAccess()
{
    if (signalHndlrObject == true)
    {
        userUpdatedSignal.reset();
        userPropertiesSignal.reset();
        sigHndlrLock.unlock();
    }
}

UserAccess::UserAccess() : bus(ipmid_get_sd_bus_connection())
{
    std::ofstream mutexCleanUpFile;
    mutexCleanUpFile.open(IPMI_MUTEX_CLEANUP_LOCK_FILE,
                          std::ofstream::out | std::ofstream::app);
    if (!mutexCleanUpFile.good())
    {
        log<level::DEBUG>("Unable to open mutex cleanup file");
        return;
    }
    mutexCleanUpFile.close();
    mutexCleanupLock =
        boost::interprocess::file_lock(IPMI_MUTEX_CLEANUP_LOCK_FILE);
    if (mutexCleanupLock.try_lock())
    {
        boost::interprocess::named_recursive_mutex::remove(IPMI_USER_MUTEX);
        userMutex =
            std::make_unique<boost::interprocess::named_recursive_mutex>(
                boost::interprocess::open_or_create, IPMI_USER_MUTEX);
        mutexCleanupLock.lock_sharable();
    }
    else
    {
        mutexCleanupLock.lock_sharable();
        userMutex =
            std::make_unique<boost::interprocess::named_recursive_mutex>(
                boost::interprocess::open_or_create, IPMI_USER_MUTEX);
    }

    initUserDataFile();
    getSystemPrivAndGroups();
    sigHndlrLock = boost::interprocess::file_lock(IPMI_USER_DATA_FILE);
    // Register it for single object and single process either netipimd /
    // host-ipmid
    if (userUpdatedSignal == nullptr && sigHndlrLock.try_lock())
    {
        log<level::DEBUG>("Registering signal handler");
        userUpdatedSignal = std::make_unique<sdbusplus::bus::match_t>(
            bus,
            sdbusplus::bus::match::rules::type::signal() +
                sdbusplus::bus::match::rules::interface(
                    DBUS_OBJ_MANAGER_INTERFACE) +
                sdbusplus::bus::match::rules::path(USER_MANAGER_OBJ_BASE_PATH),
            std::bind(userUpdatedSignalHandler, this, std::placeholders::_1));
        userPropertiesSignal = std::make_unique<sdbusplus::bus::match_t>(
            bus,
            sdbusplus::bus::match::rules::type::signal() +
                sdbusplus::bus::match::rules::path_namespace(
                    USER_MANAGER_OBJ_USERS_BASE_PATH) +
                sdbusplus::bus::match::rules::interface(
                    DBUS_PROPERTIES_INTERFACE) +
                sdbusplus::bus::match::rules::member(
                    DBUS_PROPERTIES_CHANGED_SIGNAL) +
                sdbusplus::bus::match::rules::argN(0,
                                                   USER_MANAGER_USER_INTERFACE),
            std::bind(userUpdatedSignalHandler, this, std::placeholders::_1));
        signalHndlrObject = true;
    }
}

userinfo_t *UserAccess::getUserInfo(const uint8_t &userId)
{
    checkAndReloadUserData();
    return &userDataInfo.user[userId];
}

void UserAccess::setUserInfo(const uint8_t &userId, userinfo_t *userInfo)
{
    checkAndReloadUserData();
    std::copy((uint8_t *)userInfo, (uint8_t *)userInfo + sizeof(*userInfo),
              (uint8_t *)&userDataInfo.user[userId]);
    writeUserData();
}

bool UserAccess::isValidChannel(const uint8_t &chNum)
{
    if (chNum >= IPMI_MAX_CHANNELS)
    {
        return false;
    }
    return true;
}

bool UserAccess::isValidUserId(const uint8_t &userId)
{
    if (userId > IPMI_MAX_USERS || userId == 0)
    {
        return false;
    }
    return true;
}

CommandPrivilege UserAccess::convertToIPMIPrivilege(const std::string &value)
{
    auto iter = std::find(ipmiPrivIndex.begin(), ipmiPrivIndex.end(), value);
    if (iter == ipmiPrivIndex.end())
    {
        return (CommandPrivilege)PRIVILEGE_NO_ACCESS;
    }
    else
    {
        return (CommandPrivilege)std::distance(ipmiPrivIndex.begin(), iter);
    }
}

std::string UserAccess::convertToSystemPrivilege(const CommandPrivilege &value)
{
    try
    {
        return ipmiPrivIndex.at(value);
    }
    catch (...)
    {
        log<level::ERR>("Error in converting to system privilege",
                        entry("PRIV=%d", value));
        return "";
    }
}

bool UserAccess::isValidUserName(const char *user_name)
{
    if (!user_name)
    {
        return false;
    }
    std::string userName(user_name, 0, IPMI_MAX_USER_NAME);
    if (!std::regex_match(userName.c_str(),
                          std::regex("[a-zA-z_][a-zA-Z_0-9]*")))
    {
        return false;
    }
    if (userName == "root")
    {
        return false;
    }

    auto method = bus.new_method_call(
        userMgmtService.c_str(), USER_MANAGER_OBJ_BASE_PATH,
        DBUS_OBJ_MANAGER_INTERFACE, DBUS_OBJ_MANAGER_GET_OBJ_METHOD);
    auto reply = bus.call(method);

    if (reply.is_method_error())
    {
        log<level::DEBUG>("Failed to excute method",
                          entry("METHOD=%s", OBJ_MAPPER_GET_SUBTREE_METHOD),
                          entry("PATH=%s", USER_MANAGER_OBJ_BASE_PATH));
        return false;
    }
    std::map<DbusUserObjPath, DbusUserObjValue> properties;
    reply.read(properties);

    std::string usersPath =
        std::string(USER_MANAGER_OBJ_USERS_BASE_PATH) + "/" + userName;
    if (properties.find(usersPath) != properties.end())
    {
        log<level::DEBUG>("User name already exists",
                          entry("USER_NAME=%s", userName.c_str()));
        return false;
    }

    return true;
}

ipmi_ret_t UserAccess::getUserName(const uint8_t &userId, std::string &userName)
{
    if (!isValidUserId(userId))
    {
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }
    auto userInfo = getUserInfo(userId);
    userName.assign((char *)userInfo->userName, 0, IPMI_MAX_USER_NAME);
    return IPMI_CC_OK;
}

ipmi_ret_t UserAccess::setUserName(const uint8_t &userId, const char *user_name)
{
    if (!isValidUserId(userId))
    {
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        userLock{*userMutex.get()};
    bool validUser = isValidUserName(user_name);
    std::string oldUser;
    getUserName(userId, oldUser);
    auto userInfo = getUserInfo(userId);

    std::string newUser(user_name, 0, IPMI_MAX_USER_NAME);
    if (newUser.empty() && !oldUser.empty())
    {
        // Delete existing user
        std::string userPath =
            std::string(USER_MANAGER_OBJ_USERS_BASE_PATH) + "/" + oldUser;
        auto method = bus.new_method_call(
            userMgmtService.c_str(), userPath.c_str(),
            USER_MANAGER_USER_INTERFACE, DELETE_USER_METHOD);
        auto reply = bus.call(method);
        if (reply.is_method_error())
        {
            log<level::DEBUG>("Failed to excute method",
                              entry("METHOD=%s", DELETE_USER_METHOD),
                              entry("PATH=%s", userPath.c_str()));
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
        std::fill((uint8_t *)userInfo->userName,
                  (uint8_t *)userInfo->userName + sizeof(userInfo->userName),
                  0);
        userInfo->userInSystem = 0;
        writeUserData();
    }
    else if (oldUser.empty() && !newUser.empty() && validUser)
    {
        // Create new user
        auto method = bus.new_method_call(
            userMgmtService.c_str(), USER_MANAGER_OBJ_BASE_PATH,
            USER_MANAGER_MGR_INTERFACE, CREATE_USER_METHOD);
        // TODO: Fetch proper privilege & enable state once set User access is
        // implemented
        // if LAN Channel specified, then create user for all groups
        // follow channel privilege for user creation.
        method.append(newUser.c_str(), availableGroups, "priv-admin", true);
        auto reply = bus.call(method);
        if (reply.is_method_error())
        {
            log<level::DEBUG>("Failed to excute method",
                              entry("METHOD=%s", CREATE_USER_METHOD),
                              entry("PATH=%s", USER_MANAGER_OBJ_BASE_PATH));
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
        std::strncpy((char *)userInfo->userName, user_name, IPMI_MAX_USER_NAME);
        userInfo->userInSystem = 1;
        writeUserData();
    }
    else if (oldUser != newUser && validUser)
    {
        // User rename
        auto method = bus.new_method_call(
            userMgmtService.c_str(), USER_MANAGER_OBJ_BASE_PATH,
            USER_MANAGER_MGR_INTERFACE, RENAME_USER_METHOD);
        method.append(oldUser.c_str(), newUser.c_str());
        auto reply = bus.call(method);
        if (reply.is_method_error())
        {
            log<level::DEBUG>("Failed to excute method",
                              entry("METHOD=%s", RENAME_USER_METHOD),
                              entry("PATH=%s", USER_MANAGER_OBJ_BASE_PATH));
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
        std::fill((uint8_t *)userInfo->userName,
                  (uint8_t *)userInfo->userName + sizeof(userInfo->userName),
                  0);
        std::strncpy((char *)userInfo->userName, user_name, IPMI_MAX_USER_NAME);
        userInfo->userInSystem = 1;
        writeUserData();
    }
    else if (!validUser)
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    return IPMI_CC_OK;
}

int UserAccess::readUserData()
{
    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        userLock{*userMutex.get()};

    std::ifstream iUsrData(IPMI_USER_DATA_FILE,
                           std::ios::in | std::ios::binary);
    if (!iUsrData.is_open())
    {
        log<level::DEBUG>("Error in opening IPMI user data file");
        return -1;
    }
    iUsrData.read((char *)&userDataInfo, sizeof(userDataInfo));
    if (iUsrData.fail() || (iUsrData.gcount() != sizeof(userDataInfo)))
    {
        log<level::DEBUG>("Error in reading IPMI user data file");
        return -1;
    }
    if (userDataInfo.version != USER_DATA_VERSION ||
        strcmp((char *)userDataInfo.signature, USER_DATA_SIGNATURE) != 0)
    {
        auto ver = userDataInfo.version;
        log<level::DEBUG>("IPMI user data header mismatch",
                          entry("VER=%u", ver),
                          entry("SIG=%s", userDataInfo.signature));
        return -1;
    }
    log<level::DEBUG>("User data read from IPMI dat file");
    iUsrData.close();
    // Update the timestamp
    fileLastUpdatedTime = getUpdatedFileTime();
    return 0;
}

int UserAccess::writeUserData()
{
    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        userLock{*userMutex.get()};
    std::ofstream oUsrData(IPMI_USER_DATA_FILE,
                           std::ios::out | std::ios::binary);
    if (!oUsrData.is_open())
    {
        log<level::DEBUG>("Error in creating IPMI user data file");
        return -1;
    }
    oUsrData.write((char *)&userDataInfo, sizeof(userDataInfo));
    oUsrData.flush();
    if (oUsrData.tellp() != sizeof(userDataInfo))
    {
        log<level::DEBUG>("Error in writing IPMI user data file");
        return -1;
    }
    oUsrData.close();
    // Update the timestamp
    fileLastUpdatedTime = getUpdatedFileTime();
    return 0;
}

bool UserAccess::addUserEntry(const std::string &userName,
                              const std::string &sysPriv, const bool &enabled)
{
    userdata_t *userData = getUserDataPtr();
    size_t usrIndex = 1;
    for (; usrIndex <= IPMI_MAX_USERS; ++usrIndex)
    {
        std::string curName((char *)userData->user[usrIndex].userName, 0,
                            IPMI_MAX_USER_NAME);
        if (userName == curName)
        {
            log<level::DEBUG>("User name exists",
                              entry("USER_NAME=%s", userName.c_str()));
            return false; // user name exists.
        }

        if ((!userData->user[usrIndex].userInSystem) &&
            (userData->user[usrIndex].userName[0] == '\0'))
        {
            break;
        }
    }
    if (usrIndex > IPMI_MAX_USERS)
    {
        log<level::ERR>("No empty slots found");
        return false;
    }
    std::strncpy((char *)userData->user[usrIndex].userName, userName.c_str(),
                 IPMI_MAX_USER_NAME);
    uint8_t priv =
        static_cast<uint8_t>(UserAccess::convertToIPMIPrivilege(sysPriv)) &
        PRIVILEGE_MASK;
    for (size_t chIndex = 0; chIndex < IPMI_MAX_CHANNELS; ++chIndex)
    {
        userData->user[usrIndex].userPrivAccess[chIndex].privilege = priv;
        userData->user[usrIndex].userPrivAccess[chIndex].ipmi_enabled = 0x1;
        userData->user[usrIndex].userPrivAccess[chIndex].link_auth_enabled =
            0x1;
        userData->user[usrIndex].userPrivAccess[chIndex].access_callback = 0x1;
    }
    userData->user[usrIndex].userInSystem = 1;
    userData->user[usrIndex].userEnabled = enabled;

    return true;
}

void UserAccess::deleteUserIndex(const size_t &usrIdx)
{
    userdata_t *userData = getUserDataPtr();

    std::fill((uint8_t *)userData->user[usrIdx].userName,
              (uint8_t *)userData->user[usrIdx].userName +
                  sizeof(userData->user[usrIdx].userName),
              0);
    for (size_t chIndex = 0; chIndex < IPMI_MAX_CHANNELS; ++chIndex)
    {
        userData->user[usrIdx].userPrivAccess[chIndex].privilege =
            PRIVILEGE_NO_ACCESS;
        userData->user[usrIdx].userPrivAccess[chIndex].ipmi_enabled = 0;
        userData->user[usrIdx].userPrivAccess[chIndex].link_auth_enabled = 0;
        userData->user[usrIdx].userPrivAccess[chIndex].access_callback = 0;
    }
    userData->user[usrIdx].userInSystem = 0;
    userData->user[usrIdx].userEnabled = 0;
    // TODO: Api call to update ipmi password store
    return;
}

void UserAccess::checkAndReloadUserData()
{
    std::time_t updateTime = getUpdatedFileTime();
    if (updateTime != fileLastUpdatedTime || updateTime == -1)
    {
        std::fill((uint8_t *)&userDataInfo,
                  (uint8_t *)&userDataInfo + sizeof(userDataInfo), 0);
        readUserData();
    }
    return;
}

userdata_t *UserAccess::getUserDataPtr()
{
    // reload data before using it.
    checkAndReloadUserData();
    return &userDataInfo;
}

void UserAccess::getSystemPrivAndGroups()
{
    auto method = bus.new_method_call(
        userMgmtService.c_str(), USER_MANAGER_OBJ_BASE_PATH,
        DBUS_PROPERTIES_INTERFACE, DBUS_PROPERTIES_GET_ALL_METHOD);
    method.append(USER_MANAGER_MGR_INTERFACE);

    auto reply = bus.call(method);
    if (reply.is_method_error())
    {
        log<level::DEBUG>("Failed to excute method",
                          entry("METHOD=%s", DBUS_PROPERTIES_GET_ALL_METHOD),
                          entry("PATH=%s", USER_MANAGER_OBJ_BASE_PATH));
        return;
    }
    std::map<std::string, PrivAndGroupType> properties;
    reply.read(properties);
    for (const auto &t : properties)
    {
        auto key = t.first;
        if (key == MGR_ALL_PRIV_PROP)
        {
            availablePrivileges = t.second.get<std::vector<std::string>>();
        }
        else if (key == MGR_ALL_GRPS_PROP)
        {
            availableGroups = t.second.get<std::vector<std::string>>();
        }
    }
    // TODO: Implement Supported Privilege & Groups verification logic
    return;
}

std::time_t UserAccess::getUpdatedFileTime()
{
    struct stat fileStat;
    if (stat(IPMI_USER_DATA_FILE, &fileStat) != 0)
    {
        log<level::DEBUG>("Error in getting last updated time stamp");
        return -1;
    }
    return fileStat.st_mtime;
}

void UserAccess::getUserProperties(const DbusUserObjProperties &properties,
                                   std::vector<std::string> &usrGrps,
                                   std::string &usrPriv, bool &usrEnabled)
{
    for (const auto &t : properties)
    {
        std::string key = t.first;
        if (key == USER_PRIV_PROP)
        {
            usrPriv = t.second.get<std::string>();
        }
        else if (key == USER_GROUP_PROP)
        {
            usrGrps = t.second.get<std::vector<std::string>>();
        }
        else if (key == USER_ENABLED_PROP)
        {
            usrEnabled = t.second.get<bool>();
        }
    }
    return;
}

int UserAccess::getUserObjProperties(const DbusUserObjValue &userObjs,
                                     std::vector<std::string> &usrGrps,
                                     std::string &usrPriv, bool &usrEnabled)
{
    auto usrObj = userObjs.find(USER_MANAGER_USER_INTERFACE);
    if (usrObj != userObjs.end())
    {
        getUserProperties(usrObj->second, usrGrps, usrPriv, usrEnabled);
        return 0;
    }
    return -1;
}

void UserAccess::initUserDataFile()
{
    boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
        userLock{*userMutex.get()};
    if (readUserData() != 0)
    { // File is empty, create it for the first time
        std::fill((uint8_t *)&userDataInfo,
                  (uint8_t *)&userDataInfo + sizeof(userDataInfo), 0);
        userDataInfo.version = USER_DATA_VERSION;
        std::strncpy((char *)userDataInfo.signature, USER_DATA_SIGNATURE,
                     sizeof(userDataInfo.signature));
        for (size_t userIndex = 1; userIndex <= IPMI_MAX_USERS; ++userIndex)
        {
            for (size_t chIndex = 0; chIndex < IPMI_MAX_CHANNELS; ++chIndex)
            {
                userDataInfo.user[userIndex].userPrivAccess[chIndex].privilege =
                    PRIVILEGE_NO_ACCESS;
            }
        }
        writeUserData();
    }

    auto method = bus.new_method_call(
        userMgmtService.c_str(), USER_MANAGER_OBJ_BASE_PATH,
        DBUS_OBJ_MANAGER_INTERFACE, DBUS_OBJ_MANAGER_GET_OBJ_METHOD);
    auto reply = bus.call(method);

    if (reply.is_method_error())
    {
        log<level::DEBUG>("Failed to excute method",
                          entry("METHOD=%s", OBJ_MAPPER_GET_SUBTREE_METHOD),
                          entry("PATH=%s", USER_MANAGER_OBJ_BASE_PATH));
        return;
    }

    std::map<DbusUserObjPath, DbusUserObjValue> managedObjs;
    reply.read(managedObjs);

    userdata_t *userData = &userDataInfo;
    for (size_t usrIdx = 1; usrIdx <= IPMI_MAX_USERS; ++usrIdx)
    {
        if ((userData->user[usrIdx].userInSystem) &&
            (userData->user[usrIdx].userName[0] != '\0'))
        {
            std::vector<std::string> usrGrps;
            std::string usrPriv;
            bool usrEnabled;

            std::string userName((char *)userData->user[usrIdx].userName, 0,
                                 IPMI_MAX_USER_NAME);
            std::string usersPath =
                std::string(USER_MANAGER_OBJ_USERS_BASE_PATH) + "/" + userName;

            auto usrObj = managedObjs.find(usersPath);
            if (usrObj != managedObjs.end())
            {
                // User exist. Lets check and update other fileds
                getUserObjProperties(usrObj->second, usrGrps, usrPriv,
                                     usrEnabled);
                if (std::find(usrGrps.begin(), usrGrps.end(), IPMI_GRP_NAME) ==
                    usrGrps.end())
                {
                    // Group "ipmi" is removed so lets remove user in IPMI
                    deleteUserIndex(usrIdx);
                }
                else
                {
                    // Group "ipmi" is present so lets update other properties
                    // in IPMI
                    uint8_t priv = UserAccess::convertToIPMIPrivilege(usrPriv) &
                                   PRIVILEGE_MASK;
                    for (size_t chIndex = 0; chIndex < IPMI_MAX_CHANNELS;
                         ++chIndex)
                    {
                        if (userData->user[usrIdx]
                                .userPrivAccess[chIndex]
                                .privilege != priv)
                            userData->user[usrIdx]
                                .userPrivAccess[chIndex]
                                .privilege = priv;
                    }
                    if (userData->user[usrIdx].userEnabled != usrEnabled)
                    {
                        userData->user[usrIdx].userEnabled = usrEnabled;
                    }
                }

                // We are done with this obj. lets delete from MAP
                managedObjs.erase(usrObj);
            }
            else
            {
                deleteUserIndex(usrIdx);
            }
        }
    }

    // Walk through remnaining managedObj users list
    // Add them to ipmi data base
    for (const auto &usrObj : managedObjs)
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
        if (std::find(usrGrps.begin(), usrGrps.end(), IPMI_GRP_NAME) !=
            usrGrps.end())
        {
            // CREATE NEW USER
            if (true != addUserEntry(userName, usrPriv, usrEnabled))
            {
                break;
            }
        }
    }

    // All userData slots update done. Lets write the data
    writeUserData();

    return;
}
} // namespace ipmi
