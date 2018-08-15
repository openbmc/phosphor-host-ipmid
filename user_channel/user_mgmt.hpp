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
#include <host-ipmid/ipmid-api.h>
#include <sdbusplus/bus.hpp>
#include <cstdint>
#include <ctime>
#include <boost/interprocess/sync/file_lock.hpp>
#include <boost/interprocess/sync/named_recursive_mutex.hpp>
#include "user_layer.hpp"

namespace ipmi
{

static constexpr uint8_t ipmiMaxUserName = 16;
static constexpr uint8_t ipmiMaxUsers = 15;
static constexpr uint8_t ipmiMaxChannels = 16;
static constexpr const char *ipmiUserMutex = "ipmi_usr_mutex";
static constexpr const char *ipmiMutexCleanupLockFile =
    "/var/ipmi/ipmi_usr_mutex_cleanup";

using DbusUserPropVariant =
    sdbusplus::message::variant<std::vector<std::string>, std::string, bool>;

using DbusUserObjPath = sdbusplus::message::object_path;

using DbusUserObjProperties =
    std::vector<std::pair<std::string, DbusUserPropVariant>>;

using DbusUserObjValue = std::map<std::string, DbusUserObjProperties>;

enum class UserUpdateEvent
{
    reservedEvent,
    userCreated,
    userDeleted,
    userRenamed,
    userGrpUpdated,
    userPrivUpdated,
    userStateUpdated
};

struct UserPrivAccess
{
    uint8_t privilege;
    bool ipmiEnabled;
    bool linkAuthEnabled;
    bool accessCallback;
};

struct UserInfo
{
    uint8_t userName[ipmiMaxUserName];
    UserPrivAccess userPrivAccess[ipmiMaxChannels];
    bool userEnabled;
    bool userInSystem;
    bool fixedUserName;
};

struct UsersTbl
{
    UserInfo user[ipmiMaxUsers +
                  1]; //+1 to map with UserId directly. UserId 0 is reserved.
};

class UserAccess;

UserAccess &getUserAccessObject();

class UserAccess
{
  public:
    UserAccess(const UserAccess &) = delete;
    UserAccess &operator=(const UserAccess &) = delete;
    UserAccess(UserAccess &&) = delete;
    UserAccess &operator=(UserAccess &&) = delete;

    ~UserAccess();
    UserAccess();

    static bool isValidChannel(const uint8_t &chNum);

    static bool isValidUserId(const uint8_t &userId);

    static bool isValidPrivilege(const uint8_t &priv);

    static uint8_t getUsrMgmtSyncIndex();

    static CommandPrivilege convertToIPMIPrivilege(const std::string &value);

    static std::string convertToSystemPrivilege(const CommandPrivilege &value);

    bool isValidUserName(const char *userNameInChar);

    UserInfo *getUserInfo(const uint8_t &userId);

    void setUserInfo(const uint8_t &userId, UserInfo *userInfo);

    ipmi_ret_t getUserName(const uint8_t &userId, std::string &userName);

    ipmi_ret_t setUserName(const uint8_t &userId, const char *userNameInChar);

    ipmi_ret_t setUserPrivilegeAccess(const uint8_t &userId,
                                      const uint8_t &chNum,
                                      const UserPrivAccess &privAccess,
                                      const bool &otherPrivUpdates);

    void readUserData();

    void writeUserData();

    void checkAndReloadUserData();

    void getUserProperties(const DbusUserObjProperties &properties,
                           std::vector<std::string> &usrGrps,
                           std::string &usrPriv, bool &usrEnabled);

    int getUserObjProperties(const DbusUserObjValue &userObjs,
                             std::vector<std::string> &usrGrps,
                             std::string &usrPriv, bool &usrEnabled);

    bool addUserEntry(const std::string &userName, const std::string &priv,
                      const bool &enabled);

    void deleteUserIndex(const size_t &usrIdx);

    UsersTbl *getUsersTblPtr();

    std::unique_ptr<boost::interprocess::named_recursive_mutex> userMutex{
        nullptr};

  private:
    UsersTbl usersTbl;
    std::vector<std::string> availablePrivileges;
    std::vector<std::string> availableGroups;
    sdbusplus::bus::bus bus;
    std::time_t fileLastUpdatedTime;
    bool signalHndlrObject = false;
    boost::interprocess::file_lock sigHndlrLock;
    boost::interprocess::file_lock mutexCleanupLock;
    std::time_t getUpdatedFileTime();
    void getSystemPrivAndGroups();
    void initUserDataFile();
};
} // namespace ipmi
