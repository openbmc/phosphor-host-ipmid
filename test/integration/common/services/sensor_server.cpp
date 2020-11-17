#include "common/services/sensor_server.hpp"

#include <iostream>
#include <map>
#include <memory>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/sdbus.hpp>
#include <sdbusplus/test/integration/mock_object.hpp>
#include <sdbusplus/test/integration/mock_service.hpp>
#include <string>
#include <xyz/openbmc_project/Sensor/Value/mock_server.hpp>

#include "gmock/gmock.h"

using sdbusplus::test::integration::MockObject;
using sdbusplus::test::integration::MockService;
using sdbusplus::xyz::openbmc_project::Sensor::server::MockValue;
using ::testing::NiceMock;

using SensorProperties = std::map<std::string, MockValue::PropertiesVariant>;

SensorObject::SensorObject(const std::string& path,
                           const SensorProperties& vals,
                           double changeRatePercentage) :
    MockObject(path),
    initialVals(vals), changeRate(changeRatePercentage)
{
}

void SensorObject::start(sdbusplus::bus::bus& bus)
{
    MockObject::start(bus);
    mockBase = std::make_shared<NiceMock<MockSensorObjectBase>>(
        bus, getPath().c_str());
    for (auto const& [key, val] : initialVals)
    {
        mockBase->setPropertyByName(key, val);
    }
}

std::shared_ptr<MockSensorObjectBase> SensorObject::getMockBase()
{
    return mockBase;
}

void SensorObject::toggleSensorVal()
{
    changeSensorVal(changeRate);
}

void SensorObject::changeSensorVal(double percentage)
{
    double nextSensorVal = mockBase->value() * (1 + percentage);
    mockBase->value(nextSensorVal);
}

SensorObject::~SensorObject()
{
    std::cout << getPath() << " final properties: {" << std::endl;
    std::cout << "value"
              << " : " << mockBase->value() << std::endl;
    std::cout << "}" << std::endl;
}

SensorService::SensorService(std::string name,
                             std::shared_ptr<PrivateBus> privateBus,
                             SdBusDuration microsecondsToRun,
                             SdBusDuration microsecondsBetweenSteps) :
    MockService(name, privateBus, microsecondsToRun),
    timeBetweenSteps(microsecondsBetweenSteps)
{
}

SensorService::~SensorService()
{
}

void SensorService::addSensor(const std::string& objectPath,
                              const SensorProperties& vals,
                              double changeRatePercentage)
{
    addObject(
        std::make_shared<SensorObject>(objectPath, vals, changeRatePercentage));
}

static SensorObject& getSensorObject(std::shared_ptr<MockObject> obj)
{
    return *(std::dynamic_pointer_cast<SensorObject>(obj));
}

SensorObject& SensorService::getObject(std::string path)
{
    return getSensorObject(objectRepo[path]);
}

SensorObject& SensorService::getMainObject()
{
    return getObject(mainObjectPath);
}

void SensorService::proceed()
{
    for (auto const& [path, object] : objectRepo)
    {
        getSensorObject(object).toggleSensorVal();
    }
    std::this_thread::sleep_for(timeBetweenSteps);
}

void SensorService::changeSensorVal(double percentage, std::string objectPath)
{
    SensorObject& sobj = getObject(objectPath);
    sobj.changeSensorVal(percentage);
}

void SensorService::changeMainSensorVal(double percentage)
{
    changeSensorVal(percentage, mainObjectPath);
}
