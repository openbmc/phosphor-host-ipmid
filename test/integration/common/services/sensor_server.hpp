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

/** The list of mock interfaces should be passed the template parameter
 * to this object.
 */
using MockSensorObjectBase = sdbusplus::server::object_t<MockValue>;
using SensorProperties = std::map<std::string, MockValue::PropertiesVariant>;

class SensorObject : public MockObject
{
  public:
    /** Constructs a sensor object.
     * @see SensorService.addSensor()
     */
    SensorObject(const std::string& path, const SensorProperties& vals,
                 double changeRatePercentage = 0.001);

    void changeSensorVal(double percentage);

    void toggleSensorVal();

    /** Overrides the start method in base class to initialize the sensor
     * mockBase object.
     */
    void start(sdbusplus::bus::bus& bus) override;

    virtual ~SensorObject();

    std::shared_ptr<MockSensorObjectBase> getMockBase();

  private:
    const SensorProperties& initialVals;
    double changeRate;
    /** The reference to sdbusplus object that implements MockSensor interface.
     */
    std::shared_ptr<MockSensorObjectBase> mockBase;
};

/** This service and its associated object implement sensor.Value interface.
 * In this example, it is intended to be a sensor of type temperature.
 */
class SensorService : public MockService
{
  public:
    /** Constructs this service by passing the service name, a pointer to the
     * private bus, the active duration of the service, and the time to wait
     * between each step of the main event loop that changes the sensor value.
     *
     * Note that the service does not start on D-Bus in constructor.
     * @see MockService
     */
    SensorService(std::string serviceName,
                  std::shared_ptr<PrivateBus> privateBus,
                  SdBusDuration microsecondsToRun,
                  SdBusDuration timeBetweenSteps = 1s);

    ~SensorService();

    /** Adds a new sensor object to this service.
     *
     * @param objectPath - The path of the object on D-Bus.
     * @param vals - initial sensor values.
     * @param changeRatePercentage - the rate of the changes in sensor value
     * that happens at each step of the service main event loop.
     */
    void addSensor(const std::string& objectPath, const SensorProperties& vals,
                   double changeRatePercentage = 0.001);

    SensorObject& getObject(std::string path);

    SensorObject& getMainObject();

    void changeSensorVal(double percentage, std::string objectPath);

    void changeMainSensorVal(double percentage);

  protected:
    /** An extension to the base MockService.
     *  At each step, it increases the temperature sensor value.
     */
    void proceed() override;

  private:
    SdBusDuration timeBetweenSteps;
};
