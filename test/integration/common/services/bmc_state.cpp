#include "common/services/bmc_state.hpp"

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
using sdbusplus::xyz::openbmc_project::State::server::MockBMC;
using ::testing::NiceMock;

using BMCStateProperties = std::map<std::string, MockBMC::PropertiesVariant>;

BMCStateObject::BMCStateObject(const std::string& path,
                               const BMCStateProperties& vals) :
    MockObject(path),
    initialVals(vals)
{
}

void BMCStateObject::start(sdbusplus::bus::bus& bus)
{
    MockObject::start(bus);
    mockBase =
        std::make_shared<NiceMock<MockBMCObjectBase>>(bus, getPath().c_str());
    for (auto const& [key, val] : initialVals)
    {
        mockBase->setPropertyByName(key, val);
    }
}

std::shared_ptr<MockBMCObjectBase> BMCStateObject::getMockBase()
{
    return mockBase;
}

BMCStateService::BMCStateService(std::string name,
                                 std::shared_ptr<PrivateBus> privateBus,
                                 SdBusDuration microsecondsToRun) :
    MockService(name, privateBus, microsecondsToRun)
{
}

void BMCStateService::addBMCStateObject(const std::string& objectPath,
                                        const BMCStateProperties& vals)
{
    addObject(std::make_shared<BMCStateObject>(objectPath, vals));
}

static BMCStateObject& getBMCStateObject(std::shared_ptr<MockObject> obj)
{
    return *(std::dynamic_pointer_cast<BMCStateObject>(obj));
}

BMCStateObject& BMCStateService::getObject(std::string path)
{
    return getBMCStateObject(objectRepo[path]);
}

BMCStateObject& BMCStateService::getMainObject()
{
    return getObject(mainObjectPath);
}
