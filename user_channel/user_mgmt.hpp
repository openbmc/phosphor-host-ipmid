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
#include <xyz/openbmc_project/User/UserMgr/server.hpp>
#include <cstdint>
#include <ctime>
#include <boost/interprocess/sync/file_lock.hpp>
#include <boost/interprocess/sync/named_recursive_mutex.hpp>

namespace ipmi
{

static constexpr uint8_t IPMI_MAX_USER_NAME = 16;
static constexpr uint8_t IPMI_MAX_PASSWD_SIZE = 20;
static constexpr uint8_t IPMI_MAX_USERS = 15;
static constexpr uint8_t IPMI_MAX_CHANNELS = 16;
static constexpr uint16_t USER_DATA_VERSION = 1;
static const char *USER_DATA_SIGNATURE = "OpenBMC";
static const char *IPMI_USER_MUTEX = "ipmi_usr_mutex";

static constexpr uint8_t MAX_IPMI_20_PASSWORD_SIZE = 20;
static constexpr uint8_t MAX_IPMI_15_PASSWORD_SIZE = 16;
static constexpr uint8_t DISABLE_USER = 0x00;
static constexpr uint8_t ENABLE_USER = 0x01;
static constexpr uint8_t SET_PASSWORD = 0x02;
static constexpr uint8_t TEST_PASSWORD = 0x03;

static constexpr uint8_t INVALID_USER_ID = 0x1;
static constexpr uint8_t INVALID_CH_ID = 0x1;
static constexpr uint8_t INVALID_USER_NAME = 0x1;

static constexpr size_t MAX_DBUS_OBJECT_PATH = 255;

using DbusUserPropVariant =
    sdbusplus::message::variant<std::vector<std::string>, std::string, bool>;

using DbusUserObjPath = sdbusplus::message::object_path;

using DbusUserObjProperties =
    std::vector<std::pair<std::string, DbusUserPropVariant>>;

using DbusUserObjValue = std::map<std::string, DbusUserObjProperties>;

typedef enum {
    CHAN_IPMB,       // Channel 0x00
    CHAN_LAN1,       // Channel 0x01
    CHAN_LAN2,       // Channel 0x02
    CHAN_LAN3,       // Channel 0x03
    CHAN_EMP,        // Channel 0x04
    CHAN_ICMB,       // Channel 0x05
    CHAN_SMLINK0,    // Channel 0x06
    CHAN_SMM,        // Channel 0x07
    CHAN_INTRABMC,   // Channel 0x08
    CHAN_SIPMB,      // Channel 0x09       (Secondary IPMB)
    CHAN_PCIE,       // Channel 0x0A       (PCIE slots)
    CHAN_B_RESERVED, // Channel 0x0B       (reserved)
    CHAN_INTERNAL,   // Channel 0x0C
    CHAN_D_RESERVED, // Channel 0x0D       (reserved)
    CHAN_SELF,       // Channel 0x0E       (refers to self)
    CHAN_SMS         // Channel 0x0F
} EChannelID;

typedef enum {
    RESERVED_EVENT,
    USER_CREATED,
    USER_DELETED,
    USER_RENAMED,
    USER_GRP_UPDATED,
    USER_PRIV_UPDATED,
    USER_STATE_UPDATED
} UserUpdateEvent;

struct user_priv_access
{
    uint8_t privilege : 4;
    uint8_t ipmi_enabled : 1;
    uint8_t link_auth_enabled : 1;
    uint8_t access_callback : 1;
    uint8_t reserved : 1;
} __attribute__((packed));

struct userinfo_t
{
    uint8_t userName[IPMI_MAX_USER_NAME];
    user_priv_access userPrivAccess[IPMI_MAX_CHANNELS];
    uint8_t userEnabled : 1;
    uint8_t userInSystem : 1;
    uint8_t passwordInSystem : 1;
    uint8_t passwordSet : 1;
    uint8_t fixedUserName : 1;
    uint8_t userChgInProgress : 1;
    uint8_t reserved : 2;
    uint8_t payloadEnabled[IPMI_MAX_CHANNELS];
    uint8_t payloadEnabled2[IPMI_MAX_CHANNELS];
} __attribute__((packed));

struct userdata_t
{
    uint16_t version;
    uint8_t signature[14];
    userinfo_t user[IPMI_MAX_USERS +
                    1]; //+1 to map with UserId directly. UserId 0 is reserved.
} __attribute__((packed));

using UserMgr = sdbusplus::xyz::openbmc_project::User::server::UserMgr;

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

    static CommandPrivilege convertToIPMIPrivilege(const std::string &value);

    static std::string convertToSystemPrivilege(const CommandPrivilege &value);

    bool isValidUserName(const char *user_name);

    userinfo_t *getUserInfo(const uint8_t &userId);

    void setUserInfo(const uint8_t &userId, userinfo_t *userInfo);

    int getUserName(const uint8_t &userId, std::string &userName);

    int setUserName(const uint8_t &userId, const char *user_name);

    int readUserData();

    int writeUserData();

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

    userdata_t *getUserDataPtr();

    boost::interprocess::named_recursive_mutex userMutex{
        boost::interprocess::open_or_create, IPMI_USER_MUTEX};

  private:
    userdata_t userDataInfo;
    std::vector<std::string> availablePrivileges;
    std::vector<std::string> availableGroups;
    sdbusplus::bus::bus bus;
    std::time_t fileLastUpdatedTime;
    bool signalHndlrObject = false;
    boost::interprocess::file_lock sigHndlrLock;
    std::time_t getUpdatedFileTime();
    void getSystemPrivAndGroups();
    void initUserDataFile();
};
} // namespace ipmi
