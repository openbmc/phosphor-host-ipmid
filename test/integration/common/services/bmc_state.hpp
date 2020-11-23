#pragma once

#include <map>
#include <memory>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server.hpp>
#include <sdbusplus/test/integration/mock_object.hpp>
#include <sdbusplus/test/integration/mock_service.hpp>
#include <sdbusplus/test/integration/private_bus.hpp>
#include <string>
#include <xyz/openbmc_project/State/BMC/mock_server.hpp>

using sdbusplus::SdBusDuration;
using sdbusplus::test::integration::MockObject;
using sdbusplus::test::integration::MockService;
using sdbusplus::test::integration::PrivateBus;

using sdbusplus::xyz::openbmc_project::State::server::MockBMC;
/** The list of mock interfaces is passed as the template parameter
 * to this object.
 */
using MockBMCObjectBase = sdbusplus::server::object_t<MockBMC>;
using BMCStateProperties = std::map<std::string, MockBMC::PropertiesVariant>;

class BMCStateObject : public MockObject
{
  public:
    /** Constructs a BMCStateObject object.
     * @see BMCStateService.addBMCStateObject()
     */
    BMCStateObject(const std::string& path, const BMCStateProperties& vals);
    /** Overrides the start method in base class to initialize the
     * mockBase object.
     */
    void start(sdbusplus::bus::bus& bus) override;

    std::shared_ptr<MockBMCObjectBase> getMockBase();

  private:
    const BMCStateProperties& initialVals;
    /** The reference to sdbusplus object that implements the mock interface.
     */
    std::shared_ptr<MockBMCObjectBase> mockBase;
};

/** This service and its associated object implement
 * state.BMC interface.
 */
class BMCStateService : public MockService
{
  public:
    /** Constructs this service by passing the service name, a pointer to the
     * private bus, and the active duration of the service.
     *
     * Note that the service does not start on D-Bus in constructor.
     * @see MockService
     */
    BMCStateService(std::string name, std::shared_ptr<PrivateBus> privateBus,
                    SdBusDuration microsecondsToRun);
    /** Adds a new object to this service.
     *
     * @param objectPath - The path of the object on D-Bus.
     * @param vals - initial interface values.
     */
    void addBMCStateObject(const std::string& objectPath,
                           const BMCStateProperties& vals);

    BMCStateObject& getObject(std::string path);

    BMCStateObject& getMainObject();
};
