#include "ipmid_test.hpp"

#include <chrono>
#include <sdbusplus/sdbus.hpp>

#include <gtest/gtest.h>

using ::testing::Return;

using namespace std::literals::chrono_literals;
static const auto secondsToRunTest = 5s;
static const auto uSecondsToRunTest =
    std::chrono::microseconds(secondsToRunTest);

static constexpr char defaultBMCStateServiceName[] =
    "xyz.openbmc_project.State.BMC";
static constexpr char defaultRestrictionModeServiceName[] =
    "xyz.openbmc_project.Control.Security.RestrictionMode";
static constexpr char defaultUserManagerServiceName[] =
    "xyz.openbmc_project.User.Manager";

static constexpr char defaultBMCStateObjPath[] =
    "/xyz/openbmc_project/state/bmc0";
static constexpr char defaultRestrictionModeObjPath[] = "/";
static constexpr char defaultUserManagerObjPath[] = "/xyz/openbmc_project/user";

static const BMCStateProperties defaultBMCStateVals{
    {"RequestedBMCTransition", MockBMC::Transition::None},
    {"CurrentBMCState", MockBMC::BMCState::Ready},
    {"LastRebootTime", uint64_t(1606171860)}};

static const RestrictionModeProperties defaultRestrictionModeVals{
    {"RestrictionMode", MockRestrictionMode::Modes::None}};

static const UserManagerProperties defaultUserManagerVals{
    {"AllPrivileges",
     std::vector<std::string>({"priv-reserved", "priv-callback", "priv-user",
                               "priv-operator", "priv-admin", "priv-custom"})},
    {"AllGroups", std::vector<std::string>({"ipmi"})}};

static UserProperties defaultUserVals{
    {"UserGroups", std::vector<std::string>({"ipmi"})},
    {"UserPrivilege", "priv-admin"},
    {"UserEnabled", true},
    {"UserLockedForFailedAttempt", false},
    {"RemoteUser", false},
    {"UserPasswordExpired", false}};

/* Based on data from dev_id.json */
TEST(HostIpmiCommands, DISABLED_GetDeviceIdTest)
{
    IpmidTest test;

    test.initiateRestrictionModeService(defaultRestrictionModeServiceName,
                                        uSecondsToRunTest);

    test.addNewRestrictionModeObject(defaultRestrictionModeObjPath,
                                     defaultRestrictionModeVals);

    test.startRestrictionModeService();

    test.startIpmid();

    auto response = test.executeGetDeviceId();
    const std::vector<uint8_t>& expectedResponseData{
        11, 21, 0, 0, 2, 30, 32, 0, 0, 47, 0, 50, 0, 0, 0};

    response->verify(expectedResponseData);
}

TEST(HostIpmiCommands, ColdResetTest)
{
    IpmidTest test;

    test.initiateRestrictionModeService(defaultRestrictionModeServiceName,
                                        uSecondsToRunTest);
    test.initiateBMCStateService(defaultBMCStateServiceName, uSecondsToRunTest);

    test.addNewRestrictionModeObject(defaultRestrictionModeObjPath,
                                     defaultRestrictionModeVals);
    test.addNewBMCStateObject(defaultBMCStateObjPath, defaultBMCStateVals);

    test.startRestrictionModeService();
    test.startBMCStateService();

    test.expectPropsChangedSignal(defaultBMCStateObjPath, MockBMC::interface)
        ->atLeast(1);

    test.startIpmid();

    auto response = test.executeColdReset();

    EXPECT_EQ(test.bmcStateService->getMainObject()
                  .getMockBase()
                  ->requestedBMCTransition(),
              MockBMC::Transition::Reboot);

    test.runFor(uSecondsToRunTest);

    response->verify();
}

TEST(HostIpmiCommands, GetSelfTestResultsTest)
{
    constexpr uint8_t notImplemented = 0x56;
    const std::vector<uint8_t>& expectedResponseData{notImplemented, 0};
    IpmidTest test;

    test.initiateRestrictionModeService(defaultRestrictionModeServiceName,
                                        uSecondsToRunTest);

    test.addNewRestrictionModeObject(defaultRestrictionModeObjPath,
                                     defaultRestrictionModeVals);

    test.startRestrictionModeService();

    test.startIpmid();

    auto response = test.executeGetSelfTestResults();

    response->verify(expectedResponseData);
}

TEST(HostIpmiCommands, SetUsernameTest)
{
    const std::string expectedUsername("FakeUser");
    const std::string expectedPrivilege("");
    bool expectedEnabled = false;
    uint8_t cmdArr[17] = {0};
    cmdArr[0] = 0b00000011;
    size_t i = 1;
    for (const auto c : expectedUsername)
    {
        cmdArr[i] = c;
        i++;
    }
    const std::vector<uint8_t> commandData(cmdArr, cmdArr + 17);

    IpmidTest test;

    test.initiateRestrictionModeService(defaultRestrictionModeServiceName,
                                        uSecondsToRunTest);
    test.initiateUserManagerService(defaultUserManagerServiceName,
                                    uSecondsToRunTest);

    test.addNewRestrictionModeObject(defaultRestrictionModeObjPath,
                                     defaultRestrictionModeVals);
    test.addNewUserManagerObject(defaultUserManagerObjPath,
                                 defaultUserManagerVals);

    test.startRestrictionModeService();
    test.startUserManagerService();

    test.startIpmid();

    auto expectedGroups =
        test.userManagerService->getMainObject().getMockBase()->allGroups();

    auto mockObjPtr = test.userManagerService->getMainObject().getMockBase();
    EXPECT_CALL(*mockObjPtr, createUser(expectedUsername, expectedGroups,
                                        expectedPrivilege, expectedEnabled))
        .WillOnce(Return());

    auto response = test.executeSetUsername(commandData);

    response->verifyResponse();
}

TEST(HostIpmiCommands, EnableUserTest)
{

    const std::string username("FakeUser");
    uint8_t userId = 0b00001111;
    uint8_t cmdArrUsername[17] = {0};
    cmdArrUsername[0] = userId;
    size_t i = 1;
    for (const auto c : username)
    {
        cmdArrUsername[i] = c;
        i++;
    }
    const std::vector<uint8_t> commandDataUsername(cmdArrUsername,
                                                   cmdArrUsername + 17);

    const std::string password("Bad@Pa55word");
    uint8_t cmdArr[18] = {0};
    cmdArr[0] = userId;
    cmdArr[1] = 0b00000001;
    i = 2;
    for (const auto c : password)
    {
        cmdArr[i] = c;
        i++;
    }
    const std::vector<uint8_t> commandData(cmdArr, cmdArr + 18);

    IpmidTest test;

    test.initiateRestrictionModeService(defaultRestrictionModeServiceName,
                                        uSecondsToRunTest);
    test.initiateUserManagerService(defaultUserManagerServiceName,
                                    uSecondsToRunTest);

    test.addNewRestrictionModeObject(defaultRestrictionModeObjPath,
                                     defaultRestrictionModeVals);
    test.addNewUserManagerObject(defaultUserManagerObjPath,
                                 defaultUserManagerVals);

    test.startRestrictionModeService();
    test.startUserManagerService();

    test.startIpmid();

    auto mockObjPtr = test.userManagerService->getMainObject().getMockBase();

    EXPECT_CALL(*mockObjPtr, createUser)
        .WillOnce([&test](std::string userName,
                          std::vector<std::string> groupNames,
                          std::string privilege, bool enabled) {
            defaultUserVals["UserGroups"] = groupNames;
            defaultUserVals["UserPrivilege"] = privilege;
            defaultUserVals["UserEnabled"] = enabled;
            auto path =
                std::string("/xyz/openbmc_project/user") + "/" + userName;
            test.addNewUserObject(path, defaultUserVals);
        });

    test.executeSetUsername(commandDataUsername);

    auto response = test.executeSetUserPassword(commandData);

    response->verifyResponse();
}

TEST(HostIpmiCommands, SetUserAccessTest)
{

    const std::string username("FakeUser");
    uint8_t cmdArrUsername[17] = {0};
    uint8_t userId = 0b00001111;
    cmdArrUsername[0] = userId;
    size_t i = 1;
    for (const auto c : username)
    {
        cmdArrUsername[i] = c;
        i++;
    }
    const std::vector<uint8_t> commandDataUsername(cmdArrUsername,
                                                   cmdArrUsername + 17);

    uint8_t firstByteConfig = 0b00110001;
    uint8_t userLimits = 0b00000100;
    const std::vector<uint8_t> commandDataUseraccess{firstByteConfig, userId,
                                                     userLimits};

    IpmidTest test;

    test.initiateRestrictionModeService(defaultRestrictionModeServiceName,
                                        uSecondsToRunTest);
    test.initiateUserManagerService(defaultUserManagerServiceName,
                                    uSecondsToRunTest);

    test.addNewRestrictionModeObject(defaultRestrictionModeObjPath,
                                     defaultRestrictionModeVals);
    test.addNewUserManagerObject(defaultUserManagerObjPath,
                                 defaultUserManagerVals);

    test.startRestrictionModeService();
    test.startUserManagerService();

    test.startIpmid();

    auto mockObjPtr = test.userManagerService->getMainObject().getMockBase();

    EXPECT_CALL(*mockObjPtr, createUser)
        .WillOnce([&test](std::string userName,
                          std::vector<std::string> groupNames,
                          std::string privilege, bool enabled) {
            defaultUserVals["UserGroups"] = groupNames;
            defaultUserVals["UserPrivilege"] = privilege;
            defaultUserVals["UserEnabled"] = enabled;
            auto path =
                std::string("/xyz/openbmc_project/user") + "/" + userName;
            test.addNewUserObject(path, defaultUserVals);
        });

    test.executeSetUsername(commandDataUsername);
    auto response = test.executeSetUserAccess(commandDataUseraccess);

    response->verifyResponse();
}
