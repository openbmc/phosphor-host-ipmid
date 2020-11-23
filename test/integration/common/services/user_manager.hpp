#pragma once

#include <map>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server.hpp>
#include <sdbusplus/test/integration/mock_object.hpp>
#include <sdbusplus/test/integration/mock_service.hpp>
#include <sdbusplus/test/integration/private_bus.hpp>
#include <string>
#include <xyz/openbmc_project/User/Attributes/mock_server.hpp>
#include <xyz/openbmc_project/User/Manager/mock_server.hpp>

using sdbusplus::SdBusDuration;
using sdbusplus::test::integration::MockObject;
using sdbusplus::test::integration::MockService;
using sdbusplus::test::integration::PrivateBus;
using sdbusplus::xyz::openbmc_project::User::server::MockAttributes;
using sdbusplus::xyz::openbmc_project::User::server::MockManager;

using MockUserManagerObjectBase = sdbusplus::server::object_t<MockManager>;
using MockUserObjectBase = sdbusplus::server::object_t<MockAttributes>;
using UserManagerProperties =
    std::map<std::string, MockManager::PropertiesVariant>;
using UserProperties = std::map<std::string, MockAttributes::PropertiesVariant>;

class UserManagerObject : public MockObject
{
  public:
    UserManagerObject(const std::string& path,
                      const UserManagerProperties& vals);

    void start(sdbusplus::bus::bus& bus) override;
    std::shared_ptr<MockUserManagerObjectBase> getMockBase();

  private:
    const UserManagerProperties& initialVals;
    std::shared_ptr<MockUserManagerObjectBase> mockBase;
};

class UserObject : public MockObject
{
  public:
    UserObject(const std::string& path, const UserProperties& vals);

    void start(sdbusplus::bus::bus& bus) override;
    std::shared_ptr<MockUserObjectBase> getMockBase();

  private:
    const UserProperties& initialVals;
    std::shared_ptr<MockUserObjectBase> mockBase;
};

class UserManagerService : public MockService
{
  public:
    UserManagerService(std::string name, std::shared_ptr<PrivateBus> privateBus,
                       SdBusDuration microsecondsToRun);

    void addUserManagerObject(const std::string& objectPath,
                              const UserManagerProperties& vals);

    void addUserObject(const std::string& objectPath,
                       const UserProperties& vals);

    UserObject& getUserObject(std::string path);

    UserManagerObject& getObject(std::string path);

    UserManagerObject& getMainObject();
};
