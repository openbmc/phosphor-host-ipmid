#include "common/services/restriction_mode.hpp"

#include <iostream>
#include <map>
#include <memory>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/sdbus.hpp>
#include <sdbusplus/test/integration/mock_object.hpp>
#include <sdbusplus/test/integration/mock_service.hpp>
#include <string>
#include <xyz/openbmc_project/User/Manager/mock_server.hpp>

#include "gmock/gmock.h"

using sdbusplus::test::integration::MockObject;
using sdbusplus::test::integration::MockService;
using sdbusplus::xyz::openbmc_project::Control::Security::server::
    MockRestrictionMode;
using ::testing::NiceMock;

using RestrictionModeProperties =
    std::map<std::string, MockRestrictionMode::PropertiesVariant>;

RestrictionModeObject::RestrictionModeObject(
    const std::string& path, const RestrictionModeProperties& vals) :
    MockObject(path),
    initialVals(vals)
{
}

void RestrictionModeObject::start(sdbusplus::bus::bus& bus)
{
    MockObject::start(bus);
    mockBase = std::make_shared<NiceMock<MockRestrictionModeObjectBase>>(
        bus, getPath().c_str());
    for (auto const& [key, val] : initialVals)
    {
        mockBase->setPropertyByName(key, val);
    }
}

std::shared_ptr<MockRestrictionModeObjectBase>
    RestrictionModeObject::getMockBase()
{
    return mockBase;
}

RestrictionModeService::RestrictionModeService(
    std::string name, std::shared_ptr<PrivateBus> privateBus,
    SdBusDuration microsecondsToRun) :
    MockService(name, privateBus, microsecondsToRun)
{
}

void RestrictionModeService::addRestrictionModeObject(
    const std::string& objectPath, const RestrictionModeProperties& vals)
{
    addObject(std::make_shared<RestrictionModeObject>(objectPath, vals));
}

static RestrictionModeObject&
    getRestrictionModeObject(std::shared_ptr<MockObject> obj)
{
    return *(std::dynamic_pointer_cast<RestrictionModeObject>(obj));
}

RestrictionModeObject& RestrictionModeService::getObject(std::string path)
{
    return getRestrictionModeObject(objectRepo[path]);
}

RestrictionModeObject& RestrictionModeService::getMainObject()
{
    return getObject(mainObjectPath);
}
