#include "common/services/user_manager.hpp"

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
using sdbusplus::xyz::openbmc_project::User::server::MockManager;
using ::testing::NiceMock;

using UserManagerProperties =
    std::map<std::string, MockManager::PropertiesVariant>;

UserManagerObject::UserManagerObject(const std::string& path,
                                     const UserManagerProperties& vals) :
    MockObject(path),
    initialVals(vals)
{
}

void UserManagerObject::start(sdbusplus::bus::bus& bus)
{
    MockObject::start(bus);
    mockBase = std::make_shared<NiceMock<MockUserManagerObjectBase>>(
        bus, getPath().c_str());
    for (auto const& [key, val] : initialVals)
    {
        mockBase->setPropertyByName(key, val);
    }
}

std::shared_ptr<MockUserManagerObjectBase> UserManagerObject::getMockBase()
{
    return mockBase;
}

UserObject::UserObject(const std::string& path, const UserProperties& vals) :
    MockObject(path), initialVals(vals)
{
}

void UserObject::start(sdbusplus::bus::bus& bus)
{
    MockObject::start(bus);
    mockBase =
        std::make_shared<NiceMock<MockUserObjectBase>>(bus, getPath().c_str());
    for (auto const& [key, val] : initialVals)
    {
        mockBase->setPropertyByName(key, val);
    }
}

std::shared_ptr<MockUserObjectBase> UserObject::getMockBase()
{
    return mockBase;
}

UserManagerService::UserManagerService(std::string name,
                                       std::shared_ptr<PrivateBus> privateBus,
                                       SdBusDuration microsecondsToRun) :
    MockService(name, privateBus, microsecondsToRun)
{
}

void UserManagerService::addUserManagerObject(const std::string& objectPath,
                                              const UserManagerProperties& vals)
{
    addObject(std::make_shared<UserManagerObject>(objectPath, vals));
}

static UserManagerObject& getUserManagerObject(std::shared_ptr<MockObject> obj)
{
    return *(std::dynamic_pointer_cast<UserManagerObject>(obj));
}

UserManagerObject& UserManagerService::getObject(std::string path)
{
    return getUserManagerObject(objectRepo[path]);
}

UserManagerObject& UserManagerService::getMainObject()
{
    return getObject(mainObjectPath);
}

void UserManagerService::addUserObject(const std::string& objectPath,
                                       const UserProperties& vals)
{
    addObject(std::make_shared<UserObject>(objectPath, vals));
}

UserObject& UserManagerService::getUserObject(std::string path)
{
    return *(std::dynamic_pointer_cast<UserObject>(objectRepo[path]));
}
