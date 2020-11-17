#pragma once

#include <map>
#include <memory>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server.hpp>
#include <sdbusplus/test/integration/mock_object.hpp>
#include <sdbusplus/test/integration/mock_service.hpp>
#include <sdbusplus/test/integration/private_bus.hpp>
#include <string>
#include <xyz/openbmc_project/Sensor/Value/mock_server.hpp>

using sdbusplus::SdBusDuration;
using sdbusplus::test::integration::MockObject;
using sdbusplus::test::integration::MockService;
using sdbusplus::test::integration::PrivateBus;
using sdbusplus::xyz::openbmc_project::Sensor::server::MockValue;

using MockSensorObjectBase = sdbusplus::server::object_t<MockValue>;
using SensorProperties = std::map<std::string, MockValue::PropertiesVariant>;

class SensorObject : public MockObject
{
  public:
    SensorObject(const std::string& path, const SensorProperties& vals,
                 double changeRatePercentage = 0.001);

    void changeSensorVal(double percentage);

    void toggleSensorVal();

    void start(sdbusplus::bus::bus& bus) override;

    virtual ~SensorObject();

    std::shared_ptr<MockSensorObjectBase> getMockBase();

  private:
    const SensorProperties& initialVals;
    double changeRate;
    std::shared_ptr<MockSensorObjectBase> mockBase;
};

class SensorService : public MockService
{
  public:
    SensorService(std::string serviceName,
                  std::shared_ptr<PrivateBus> privateBus,
                  SdBusDuration microsecondsToRun,
                  SdBusDuration timeBetweenSteps = 1s);

    ~SensorService();

    void addSensor(const std::string& objectPath, const SensorProperties& vals,
                   double changeRatePercentage = 0.001);

    SensorObject& getObject(std::string path);

    SensorObject& getMainObject();

    void changeSensorVal(double percentage, std::string objectPath);

    void changeMainSensorVal(double percentage);

  protected:
    void proceed() override;

  private:
    SdBusDuration timeBetweenSteps;
};
