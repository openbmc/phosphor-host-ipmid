#include "ipmid_test.hpp"

#include <chrono>
#include <sdbusplus/sdbus.hpp>

#include <gtest/gtest.h>

using ::testing::Return;

using namespace std::literals::chrono_literals;
static const auto secondsToRunTest = 6s;
static const auto uSecondsToRunTest =
    std::chrono::microseconds(secondsToRunTest);

static constexpr char defaultRestrictionModeServiceName[] =
    "xyz.openbmc_project.Control.Security.RestrictionMode";
static constexpr char defaultTempServiceName[] =
    "xyz.openbmc_project.Hwmon-1644477290.Hwmon0";

static constexpr char defaultRestrictionModeObjPath[] = "/";

static constexpr char defaultTempObjPath[] =
    "/xyz/openbmc_project/sensors/temperature/fleeting0";

static const RestrictionModeProperties defaultRestrictionModeVals{
    {"RestrictionMode", MockRestrictionMode::Modes::None}};

static const SensorProperties defaultTempVals{
    {"Value", 18.4 * 512000},
    {"MaxValue", 100.0 * 512000},
    {"MinValue", 0.4 * 512000},
    {"Unit", MockValue::Unit::DegreesC},
    {"Scale", 0.0},
};

TEST(HostIpmiCommands, GetDeviceSdrInfoTest)
{
    const std::vector<uint8_t> commandData{0};
    IpmidTest test;

    test.initiateRestrictionModeService(defaultRestrictionModeServiceName,
                                        uSecondsToRunTest);

    test.addNewRestrictionModeObject(defaultRestrictionModeObjPath,
                                     defaultRestrictionModeVals);

    test.startRestrictionModeService();

    test.startIpmid();

    const std::vector<uint8_t>& expectedResponseData{7, 1};

    auto response = test.executeGetDeviceSdrInfo(commandData);

    response->verify(expectedResponseData);
}

TEST(HostIpmiCommands, GetDeviceSdrTest)
{
    const std::vector<uint8_t> commandData{0, 0, 0, 0, 0, 0xff};
    IpmidTest test;

    test.initiateRestrictionModeService(defaultRestrictionModeServiceName,
                                        uSecondsToRunTest);

    test.addNewRestrictionModeObject(defaultRestrictionModeObjPath,
                                     defaultRestrictionModeVals);

    test.startRestrictionModeService();

    test.startIpmid();

    auto response = test.executeGetDeviceSdr(commandData);

    response->verifyResponse();
}

/* Based on data from phosphor-host-ipmid/scripts/sensor-example.yaml
To make this test work, the type of sensor values defined in
sensor-example.yaml, should be double (same as what is defined in
phosphor-dbus-interfaces)
*/
TEST(HostIpmiCommands, DISABLED_GetSensorReadingTest)
{
    const std::vector<uint8_t> commandData{0xD0};
    IpmidTest test;

    test.initiateTempService(defaultTempServiceName, uSecondsToRunTest);
    test.initiateRestrictionModeService(defaultRestrictionModeServiceName,
                                        uSecondsToRunTest);

    test.addNewTempObject(defaultTempObjPath, defaultTempVals);
    test.addNewRestrictionModeObject(defaultRestrictionModeObjPath,
                                     defaultRestrictionModeVals);

    test.startTempService();
    test.startRestrictionModeService();

    test.startIpmid();

    auto response = test.executeGetSensorReading();

    uint8_t sensorVal =
        test.tempService->getMainObject().getMockBase()->value() / 512000.0;
    const std::vector<uint8_t>& expectedResponseData{sensorVal, 0x40, 0, 0};

    test.runFor(uSecondsToRunTest);

    response->verify(expectedResponseData);
}
