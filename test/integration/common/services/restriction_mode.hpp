#pragma once

#include <map>
#include <memory>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server.hpp>
#include <sdbusplus/test/integration/mock_object.hpp>
#include <sdbusplus/test/integration/mock_service.hpp>
#include <sdbusplus/test/integration/private_bus.hpp>
#include <string>
#include <xyz/openbmc_project/Control/Security/RestrictionMode/mock_server.hpp>

using sdbusplus::SdBusDuration;
using sdbusplus::test::integration::MockObject;
using sdbusplus::test::integration::MockService;
using sdbusplus::test::integration::PrivateBus;
using sdbusplus::xyz::openbmc_project::Control::Security::server::
    MockRestrictionMode;

/** The list of mock interfaces is passed as the template parameter
 * to this object.
 */
using MockRestrictionModeObjectBase =
    sdbusplus::server::object_t<MockRestrictionMode>;
using RestrictionModeProperties =
    std::map<std::string, MockRestrictionMode::PropertiesVariant>;

class RestrictionModeObject : public MockObject
{
  public:
    /** Constructs a RestrictionMode object.
     * @see RestrictionModeService.addRestrictionModeObject()
     */
    RestrictionModeObject(const std::string& path,
                          const RestrictionModeProperties& vals);

    /** Overrides the start method in base class to initialize the
     * mockBase object.
     */
    void start(sdbusplus::bus::bus& bus) override;

    std::shared_ptr<MockRestrictionModeObjectBase> getMockBase();

  private:
    const RestrictionModeProperties& initialVals;
    /** The reference to sdbusplus object that implements the mock interface.
     */
    std::shared_ptr<MockRestrictionModeObjectBase> mockBase;
};

/** This service and its associated object implement
 * control.Security.RestrictionMode interface.
 */
class RestrictionModeService : public MockService
{
  public:
    /** Constructs this service by passing the service name, a pointer to the
     * private bus, and the active duration of the service.
     *
     * Note that the service does not start on D-Bus in constructor.
     * @see MockService
     */
    RestrictionModeService(std::string name,
                           std::shared_ptr<PrivateBus> privateBus,
                           SdBusDuration microsecondsToRun);
    /** Adds a new object to this service.
     *
     * @param objectPath - The path of the object on D-Bus.
     * @param vals - initial interface values.
     */
    void addRestrictionModeObject(const std::string& objectPath,
                                  const RestrictionModeProperties& vals);

    RestrictionModeObject& getObject(std::string path);

    RestrictionModeObject& getMainObject();
};
