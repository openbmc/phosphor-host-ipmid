#pragma once

#include <map>
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

using MockRestrictionModeObjectBase =
    sdbusplus::server::object_t<MockRestrictionMode>;
using RestrictionModeProperties =
    std::map<std::string, MockRestrictionMode::PropertiesVariant>;

class RestrictionModeObject : public MockObject
{
  public:
    RestrictionModeObject(const std::string& path,
                          const RestrictionModeProperties& vals);

    void start(sdbusplus::bus::bus& bus) override;

    std::shared_ptr<MockRestrictionModeObjectBase> getMockBase();

  private:
    const RestrictionModeProperties& initialVals;
    std::shared_ptr<MockRestrictionModeObjectBase> mockBase;
};

class RestrictionModeService : public MockService
{
  public:
    RestrictionModeService(std::string name,
                           std::shared_ptr<PrivateBus> privateBus,
                           SdBusDuration microsecondsToRun);

    void addRestrictionModeObject(const std::string& objectPath,
                                  const RestrictionModeProperties& vals);

    RestrictionModeObject& getObject(std::string path);

    RestrictionModeObject& getMainObject();
};
