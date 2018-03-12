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
#include <host-ipmid/ipmid-api.h>
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

namespace ipmi {

static constexpr auto IPMI_USER_DATA_FILE = "/var/ipmi_user.dat";

// User manager related
static constexpr char USER_MANAGER_SERVICE[] =
    "xyz.openbmc_project.User.Manager";
static constexpr char USER_MANAGER_OBJ_BASE_PATH[] =
    "/xyz/openbmc_project/user";
static constexpr char USER_MANAGER_OBJ_USERS_BASE_PATH[] =
    "/xyz/openbmc_project/user/Users";
static constexpr char USER_MANAGER_MGR_INTERFACE[] =
    "xyz.openbmc_project.User.UserMgr";
static constexpr char USER_MANAGER_USER_INTERFACE[] =
    "xyz.openbmc_project.User.Users";
static constexpr char ADD_USER_METHOD[] = "AddUser";
static constexpr char DELETE_USER_METHOD[] = "DeleteUser";

// D-Bus property related
static constexpr char DBUS_PROPERTIES_INTERFACE[] =
    "org.freedesktop.DBus.Properties";
static constexpr char DBUS_PROPERTIES_GET_ALL_METHOD[] = "GetAll";

// Object Manager related
static constexpr char DBUS_OBJ_MANAGER_INTERFACE[] =
    "org.freedesktop.DBus.ObjectManager";
static constexpr char DBUS_OBJ_MANAGER_GET_OBJ_METHOD[] = "GetManagedObjects";

// Object Mapper related
static constexpr char OBJ_MAPPER_SERVICE[] = "xyz.openbmc_project.ObjectMapper";
static constexpr char OBJ_MAPPER_OBJ_PATH[] =
    "/xyz/openbmc_project/object_mapper";
static constexpr char OBJ_MAPPER_INTERFACE[] =
    "xyz.openbmc_project.ObjectMapper";
static constexpr char OBJ_MAPPER_GET_SUBTREE_METHOD[] = "GetSubTree";

using PrivAndGroupType =
    sdbusplus::message::variant<std::string, std::vector<std::string>>;

using NoResource =
    sdbusplus::xyz::openbmc_project::User::Common::Error::NoResource;

using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

std::unique_ptr<sdbusplus::bus::match_t> userUpdatedSignal(nullptr);

void userUpdatedSignalHandler(UserAccess *usrAccess,
                              sdbusplus::message::message &msg) {
  std::string userName, update, priv;
  std::vector<std::string> groups;
  log<level::ERR>("userUpdatedSignalHandler");
  msg.read(update, userName, groups, priv);
  log<level::ERR>("userUpdatedSignalHandler After Msg read");
  if (userName.empty() || update.empty()) {
    log<level::ERR>("Received Empty user name / update");
    return;
  }
  boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
      userLock{usrAccess->userMutex};
  UserMgr::UserUpdate userUpdate = UserMgr::convertUserUpdateFromString(update);
  userdata_t *userData = usrAccess->getUserDataPtr();
  switch (userUpdate) {
    case UserMgr::UserUpdate::Added: {
      size_t emptySlot = 0xFF;
      for (size_t count = 1; count < IPMI_MAX_USERS; ++count) {
        std::string curName((char *)userData->user[count].userName, 0,
                            IPMI_MAX_USER_NAME);
        if (userName == curName) {
          log<level::DEBUG>("User name exists",
                            entry("USER_NAME=%s", userName.c_str()));
          return;  // user name exists.
        }
        if ((!userData->user[count].userInSystem) &&
            (userData->user[count].userName[0] == '\0') && emptySlot == 0xFF) {
          emptySlot = count;
        }
      }
      if (emptySlot == 0xFF) {
        log<level::ERR>("No empty slots to add user",
                        entry("USER_NAME=%s", userName.c_str()));
        return;
      }
      std::strncpy((char *)userData->user[emptySlot].userName, userName.c_str(),
                   IPMI_MAX_USER_NAME);
      // TODO: Do the privilege conversion and update to the requested one
      for (size_t chCount = 0; chCount < IPMI_MAX_CHANNELS; ++chCount) {
        userData->user[emptySlot].userPrivAccess[chCount].privilege =
            PRIVILEGE_ADMIN;
        userData->user[emptySlot].userPrivAccess[chCount].ipmi_enabled = 0x1;
        userData->user[emptySlot].userPrivAccess[chCount].link_auth_enabled =
            0x1;
        userData->user[emptySlot].userPrivAccess[chCount].access_callback = 0x1;
      }
      userData->user[emptySlot].userInSystem = 1;
      usrAccess->writeUserData();
      log<level::DEBUG>("UserUpdatedSignal - Added successfully",
                        entry("USER_NAME=%s", userName),
                        entry("USER_ID=%d", emptySlot));
      return;
    }
    case UserMgr::UserUpdate::Deleted: {
      for (size_t count = 1; count < IPMI_MAX_USERS; ++count) {
        std::string curName((char *)userData->user[count].userName, 0,
                            IPMI_MAX_USER_NAME);
        if (userName == curName) {
          std::fill((uint8_t *)userData->user[count].userName,
                    (uint8_t *)userData->user[count].userName +
                        sizeof(userData->user[count].userName),
                    0);
          for (size_t chCount = 0; chCount < IPMI_MAX_CHANNELS; ++chCount) {
            userData->user[count].userPrivAccess[chCount].privilege = 0;
            userData->user[count].userPrivAccess[chCount].ipmi_enabled = 0;
            userData->user[count].userPrivAccess[chCount].link_auth_enabled = 0;
            userData->user[count].userPrivAccess[chCount].access_callback = 0;
          }
          userData->user[count].userChgInProgress = 0;
          userData->user[count].userInSystem = 0;
          usrAccess->writeUserData();
          log<level::DEBUG>("UserUpdatedSignal - Deleted",
                            entry("USER_NAME=%s", userName),
                            entry("USER_ID=%d", count));
          return;
        }
      }
      log<level::DEBUG>("UserUpdatedSignal - Deleted - User not found",
                        entry("USER_NAME=%s", userName.c_str()));
      return;
    }
    // TODO:  Do for Role & Group Update
    default:
      log<level::ERR>("UserUpdatedSignal- TODO - Yet-to-implement",
                      entry("SIGNAL=%s", update));

      return;
  }
}

UserAccess::~UserAccess() {
  boost::interprocess::named_recursive_mutex::remove(IPMI_USER_MUTEX);
  if (signalHndlrObject == true) {
    userUpdatedSignal.reset();
    sigHndlrLock.unlock();
  }
}

UserAccess::UserAccess() : bus(ipmid_get_sd_bus_connection()) {
  initUserDataFile();
  getSystemPrivAndGroups();

  sigHndlrLock = boost::interprocess::file_lock(IPMI_USER_DATA_FILE);
  // Register it for single object and single process either netipimd /
  // host-ipmid
  if (userUpdatedSignal == nullptr && sigHndlrLock.try_lock()) {
    log<level::DEBUG>("Registering signal handler");
    userUpdatedSignal = std::make_unique<sdbusplus::bus::match_t>(
        bus,
        sdbusplus::bus::match::rules::type::signal() +
            sdbusplus::bus::match::rules::member("UserUpdated") +
            sdbusplus::bus::match::rules::path(USER_MANAGER_OBJ_BASE_PATH) +
            sdbusplus::bus::match::rules::interface(USER_MANAGER_MGR_INTERFACE),
        std::bind(userUpdatedSignalHandler, this, std::placeholders::_1));
    signalHndlrObject = true;
  }
}

userinfo_t *UserAccess::getUserInfo(uint8_t userId) {
  checkAndReloadUserData();
  return &userDataInfo.user[userId];
}

void UserAccess::setUserInfo(uint8_t userId, userinfo_t *userInfo) {
  checkAndReloadUserData();
  std::copy((uint8_t *)userInfo, (uint8_t *)userInfo + sizeof(*userInfo),
            (uint8_t *)&userDataInfo.user[userId]);
  writeUserData();
}

bool UserAccess::isValidChannel(uint8_t chNum) {
  if (chNum >= IPMI_MAX_CHANNELS) {
    return false;
  }
  return true;
}

bool UserAccess::isValidUserId(uint8_t userId) {
  if (userId >= IPMI_MAX_USERS || userId == 0) {
    return false;
  }
  return true;
}

bool UserAccess::isValidUserName(const char *user_name) {
  if (!user_name) {
    return false;
  }
  std::string userName(user_name, 0, IPMI_MAX_USER_NAME);
  if (!std::regex_match(userName.c_str(),
                        std::regex("[a-zA-z_][a-zA-Z_0-9]*"))) {
    return false;
  }
  if (userName == "root") {
    return false;
  }

  auto method = bus.new_method_call(
      USER_MANAGER_SERVICE, USER_MANAGER_OBJ_BASE_PATH,
      DBUS_OBJ_MANAGER_INTERFACE, DBUS_OBJ_MANAGER_GET_OBJ_METHOD);
  auto reply = bus.call(method);

  if (reply.is_method_error()) {
    log<level::DEBUG>("Failed to excute method",
                      entry("METHOD=%s", OBJ_MAPPER_GET_SUBTREE_METHOD),
                      entry("PATH=%s", USER_MANAGER_OBJ_BASE_PATH));
    return false;
  }
  std::map<sdbusplus::message::object_path,
           std::vector<
               std::pair<std::string, std::map<std::string, PrivAndGroupType>>>>
      properties;
  reply.read(properties);

  std::string usersPath =
      std::string(USER_MANAGER_OBJ_USERS_BASE_PATH) + "/" + userName;
  if (properties.find(usersPath) != properties.end()) {
    log<level::DEBUG>("User name already exists",
                      entry("USER_NAME=%s", userName.c_str()));
    return false;
  }

  return true;
}

int UserAccess::getUserName(uint8_t userId, std::string &userName) {
  if (!isValidUserId(userId)) {
    return INVALID_USER_ID;
  }
  auto userInfo = getUserInfo(userId);
  userName.assign((char *)userInfo->userName, 0, IPMI_MAX_USER_NAME);
  return 0;
}

int UserAccess::setUserName(uint8_t userId, const char *user_name) {
  if (!isValidUserId(userId)) {
    return INVALID_USER_ID;
  }

  boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
      userLock{userMutex};
  bool validUser = isValidUserName(user_name);
  std::string oldUser;
  getUserName(userId, oldUser);
  auto userInfo = getUserInfo(userId);

  std::string newUser(user_name, 0, IPMI_MAX_USER_NAME);
  if (newUser.empty() && !oldUser.empty()) {
    // Delete existing user
    auto method =
        bus.new_method_call(USER_MANAGER_SERVICE, USER_MANAGER_OBJ_BASE_PATH,
                            USER_MANAGER_MGR_INTERFACE, DELETE_USER_METHOD);
    method.append(oldUser.c_str());
    auto reply = bus.call(method);
    if (reply.is_method_error()) {
      log<level::DEBUG>("Failed to excute method",
                        entry("METHOD=%s", DELETE_USER_METHOD),
                        entry("PATH=%s", USER_MANAGER_OBJ_BASE_PATH));
      return IPMI_CC_UNSPECIFIED_ERROR;
    }
    std::fill((uint8_t *)userInfo->userName,
              (uint8_t *)userInfo->userName + sizeof(userInfo->userName), 0);
    userInfo->userInSystem = 0;
    writeUserData();
  } else if (oldUser.empty() && !newUser.empty() && validUser) {
    // Create new user
    auto method =
        bus.new_method_call(USER_MANAGER_SERVICE, USER_MANAGER_OBJ_BASE_PATH,
                            USER_MANAGER_MGR_INTERFACE, ADD_USER_METHOD);
    // TODO: Fetch proper role & group
    // if LAN Channel specified, then create user for all groups
    // follow channel privilege for user creation.
    method.append(newUser.c_str(), availableGroups, "priv-admin");
    auto reply = bus.call(method);
    if (reply.is_method_error()) {
      log<level::DEBUG>("Failed to excute method",
                        entry("METHOD=%s", ADD_USER_METHOD),
                        entry("PATH=%s", USER_MANAGER_OBJ_BASE_PATH));
      return IPMI_CC_UNSPECIFIED_ERROR;
    }
    std::strncpy((char *)userInfo->userName, user_name, IPMI_MAX_USER_NAME);
    userInfo->userInSystem = 1;
    writeUserData();
  } else if (oldUser != newUser && validUser) {
    // Update by deleting old user and creating new one
    auto method =
        bus.new_method_call(USER_MANAGER_SERVICE, USER_MANAGER_OBJ_BASE_PATH,
                            USER_MANAGER_MGR_INTERFACE, DELETE_USER_METHOD);
    method.append(oldUser.c_str());
    auto reply = bus.call(method);
    if (reply.is_method_error()) {
      log<level::DEBUG>("Failed to excute method",
                        entry("METHOD=%s", DELETE_USER_METHOD),
                        entry("PATH=%s", USER_MANAGER_OBJ_BASE_PATH));
      return IPMI_CC_UNSPECIFIED_ERROR;
    }
    std::fill((uint8_t *)userInfo->userName,
              (uint8_t *)userInfo->userName + sizeof(userInfo->userName), 0);
    userInfo->userInSystem = 0;
    writeUserData();
    method =
        bus.new_method_call(USER_MANAGER_SERVICE, USER_MANAGER_OBJ_BASE_PATH,
                            USER_MANAGER_MGR_INTERFACE, ADD_USER_METHOD);
    // TODO: Fetch proper role & group
    // if LAN Channel specified, then create user for all groups
    // follow channel privilege for user creation.
    method.append(newUser.c_str(), availableGroups, "priv-admin");
    reply = bus.call(method);
    if (reply.is_method_error()) {
      log<level::DEBUG>("Failed to excute method",
                        entry("METHOD=%s", ADD_USER_METHOD),
                        entry("PATH=%s", USER_MANAGER_OBJ_BASE_PATH));
      return IPMI_CC_UNSPECIFIED_ERROR;
    }
    std::fill((uint8_t *)userInfo->userName,
              (uint8_t *)userInfo->userName + sizeof(userInfo->userName), 0);
    std::strncpy((char *)userInfo->userName, user_name, IPMI_MAX_USER_NAME);
    userInfo->userInSystem = 1;
    writeUserData();
  } else if (!validUser) {
    return INVALID_USER_NAME;
  }
  return 0;
}

int UserAccess::readUserData() {
  boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
      userLock{userMutex};

  std::ifstream iUsrData(IPMI_USER_DATA_FILE, std::ios::in | std::ios::binary);
  if (!iUsrData.is_open()) {
    log<level::DEBUG>("Error in opening IPMI user data file");
    return -1;
  }
  iUsrData.read((char *)&userDataInfo, sizeof(userDataInfo));
  if (iUsrData.fail() || (iUsrData.gcount() != sizeof(userDataInfo))) {
    log<level::DEBUG>("Error in reading IPMI user data file");
    return -1;
  }
  if (userDataInfo.version != USER_DATA_VERSION ||
      strcmp((char *)userDataInfo.signature, USER_DATA_SIGNATURE) != 0) {
    auto ver = userDataInfo.version;
    log<level::DEBUG>("IPMI user data header mismatch", entry("VER=%u", ver),
                      entry("SIG=%s", userDataInfo.signature));
    return -1;
  }
  log<level::DEBUG>("User data read from IPMI dat file");
  iUsrData.close();
  // Update the timestamp
  fileLastUpdatedTime = getUpdatedFileTime();
  return 0;
}

int UserAccess::writeUserData() {
  boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
      userLock{userMutex};
  std::ofstream oUsrData(IPMI_USER_DATA_FILE, std::ios::out | std::ios::binary);
  if (!oUsrData.is_open()) {
    log<level::DEBUG>("Error in creating IPMI user data file");
    return -1;
  }
  oUsrData.write((char *)&userDataInfo, sizeof(userDataInfo));
  oUsrData.flush();
  if (oUsrData.tellp() != sizeof(userDataInfo)) {
    log<level::DEBUG>("Error in writing IPMI user data file");
    return -1;
  }
  oUsrData.close();
  // Update the timestamp
  fileLastUpdatedTime = getUpdatedFileTime();
  return 0;
}

void UserAccess::checkAndReloadUserData() {
  std::time_t updateTime = getUpdatedFileTime();
  if (updateTime != fileLastUpdatedTime || updateTime == -1) {
    std::fill((uint8_t *)&userDataInfo,
              (uint8_t *)&userDataInfo + sizeof(userDataInfo), 0);
    readUserData();
  }
  return;
}

userdata_t *UserAccess::getUserDataPtr() {
  // reload the data before using it.
  checkAndReloadUserData();
  return &userDataInfo;
}

void UserAccess::getSystemPrivAndGroups() {
  auto method = bus.new_method_call(
      USER_MANAGER_SERVICE, USER_MANAGER_OBJ_BASE_PATH,
      DBUS_PROPERTIES_INTERFACE, DBUS_PROPERTIES_GET_ALL_METHOD);
  method.append(USER_MANAGER_MGR_INTERFACE);

  auto reply = bus.call(method);
  if (reply.is_method_error()) {
    log<level::DEBUG>("Failed to excute method",
                      entry("METHOD=%s", DBUS_PROPERTIES_GET_ALL_METHOD),
                      entry("PATH=%s", USER_MANAGER_OBJ_BASE_PATH));
    return;
  }
  std::map<std::string, PrivAndGroupType> properties;
  reply.read(properties);
  for (const auto &t : properties) {
    auto key = t.first;
    if (key == "ListPrivileges") {
      availablePrivileges = t.second.get<std::vector<std::string>>();
    } else if (key == "ListGroups") {
      availableGroups = t.second.get<std::vector<std::string>>();
    }
  }
  // TODO: Implement Supported Privilege & Groups verification logic
  return;
}

std::time_t UserAccess::getUpdatedFileTime() {
  struct stat fileStat;
  if (stat(IPMI_USER_DATA_FILE, &fileStat) != 0) {
    log<level::DEBUG>("Error in getting last updated time stamp");
    return -1;
  }
  return fileStat.st_mtime;
}

void UserAccess::initUserDataFile() {
  boost::interprocess::scoped_lock<boost::interprocess::named_recursive_mutex>
      userLock{userMutex};
  if (readUserData() != 0) {  // File is empty, create it for the first time
    std::fill((uint8_t *)&userDataInfo,
              (uint8_t *)&userDataInfo + sizeof(userDataInfo), 0);
    userDataInfo.version = USER_DATA_VERSION;
    std::strncpy((char *)userDataInfo.signature, USER_DATA_SIGNATURE,
                 sizeof(userDataInfo.signature));

    // TODO: Remove below block of code. Time being add root user here in
    // user ID 1
    std::strncpy((char *)userDataInfo.user[1].userName, "root",
                 sizeof(userDataInfo.user[1].userName));
    for (auto i = 0; i < IPMI_MAX_CHANNELS; ++i) {
      userDataInfo.user[1].userPrivAccess[i].privilege = PRIVILEGE_ADMIN;
      userDataInfo.user[1].userPrivAccess[i].ipmi_enabled = 0x1;
      userDataInfo.user[1].userPrivAccess[i].link_auth_enabled = 0x1;
      userDataInfo.user[1].userPrivAccess[i].access_callback = 0x1;
    }
    userDataInfo.user[1].userEnabled = 1;
    userDataInfo.user[1].userInSystem = 1;
    userDataInfo.user[1].fixedUserName = 1;
    userDataInfo.user[1].passwordInSystem = 0;
    // TODO: Remove above block of code. Time being add root user here in
    // user ID 1

    writeUserData();
  }
  return;
}
}
