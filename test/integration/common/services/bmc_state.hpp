#pragma once

#include <map>
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

using MockBMCObjectBase = sdbusplus::server::object_t<MockBMC>;
using BMCStateProperties = std::map<std::string, MockBMC::PropertiesVariant>;

class BMCStateObject : public MockObject
{
  public:
    BMCStateObject(const std::string& path, const BMCStateProperties& vals);

    void start(sdbusplus::bus::bus& bus) override;

    std::shared_ptr<MockBMCObjectBase> getMockBase();

  private:
    const BMCStateProperties& initialVals;
    std::shared_ptr<MockBMCObjectBase> mockBase;
};

class BMCStateService : public MockService
{
  public:
    BMCStateService(std::string name, std::shared_ptr<PrivateBus> privateBus,
                    SdBusDuration microsecondsToRun);

    void addBMCStateObject(const std::string& objectPath,
                           const BMCStateProperties& vals);

    BMCStateObject& getObject(std::string path);

    BMCStateObject& getMainObject();
};
