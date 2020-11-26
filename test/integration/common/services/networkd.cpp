#include "common/services/networkd.hpp"

#include <memory>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/sdbus.hpp>
#include <string>

#include "gmock/gmock.h"

using ::testing::NiceMock;

NetworkManagerObject::NetworkManagerObject(const std::string& path) :
    MockObject(path)
{
}

void NetworkManagerObject::start(sdbusplus::bus::bus& bus)
{
    MockObject::start(bus);
    mockBase = std::make_shared<NiceMock<MockNetworkManagerObjectBase>>(
        bus, getPath().c_str());
}

std::shared_ptr<MockNetworkManagerObjectBase>
    NetworkManagerObject::getMockBase()
{
    return mockBase;
}

EthernetInterfaceObject::EthernetInterfaceObject(
    const std::string& path, const EthernetInterfaceProperties& ethIfaceVals) :
    MockObject(path),
    initialEthIfaceVals(ethIfaceVals)
{
}

void EthernetInterfaceObject::start(sdbusplus::bus::bus& bus)
{
    MockObject::start(bus);
    mockBase = std::make_shared<NiceMock<MockEthernetInterfaceObjectBase>>(
        bus, getPath().c_str());
    for (auto const& [key, val] : initialEthIfaceVals)
    {
        mockBase->MockEthernetInterface::setPropertyByName(key, val);
    }
}

std::shared_ptr<MockEthernetInterfaceObjectBase>
    EthernetInterfaceObject::getMockBase()
{
    return mockBase;
}

VLANInterfaceObject::VLANInterfaceObject(
    const std::string& path, const VLANProperties& vLanVals,
    const EthernetInterfaceProperties& ethIfaceVals) :
    MockObject(path),
    initialVLanVals(vLanVals), initialEthIfaceVals(ethIfaceVals)
{
}

void VLANInterfaceObject::start(sdbusplus::bus::bus& bus)
{
    MockObject::start(bus);
    mockBase =
        std::make_shared<NiceMock<MockVLANObjectBase>>(bus, getPath().c_str());
    for (auto const& [key, val] : initialVLanVals)
    {
        mockBase->MockVLAN::setPropertyByName(key, val);
    }
    for (auto const& [key, val] : initialEthIfaceVals)
    {
        mockBase->MockEthernetInterface::setPropertyByName(key, val);
    }
}

std::shared_ptr<MockVLANObjectBase> VLANInterfaceObject::getMockBase()
{
    return mockBase;
}

SystemConfigurationObject::SystemConfigurationObject(
    const std::string& path, const SystemConfigurationProperties& sysConfVals) :
    MockObject(path),
    initialSysConfVals(sysConfVals)
{
}

void SystemConfigurationObject::start(sdbusplus::bus::bus& bus)
{
    MockObject::start(bus);
    mockBase = std::make_shared<NiceMock<MockSystemConfigurationObjectBase>>(
        bus, getPath().c_str());
    for (auto const& [key, val] : initialSysConfVals)
    {
        mockBase->setPropertyByName(key, val);
    }
}

std::shared_ptr<MockSystemConfigurationObjectBase>
    SystemConfigurationObject::getMockBase()
{
    return mockBase;
}

NetworkDService::NetworkDService(std::string name,
                                 std::shared_ptr<PrivateBus> privateBus,
                                 SdBusDuration microsecondsToRun) :
    MockService(name, privateBus, microsecondsToRun)
{
}

void NetworkDService::addSystemConfigurationObject(
    const std::string& objectPath, const SystemConfigurationProperties& vals)
{
    addObject(std::make_shared<SystemConfigurationObject>(objectPath, vals));
}

void NetworkDService::addEthernetInterfaceObject(
    const std::string& objectPath,
    const EthernetInterfaceProperties& ethIfacevals)
{
    addObject(
        std::make_shared<EthernetInterfaceObject>(objectPath, ethIfacevals));
}

void NetworkDService::addNetworkManagerObject(const std::string& objectPath)
{
    addObject(std::make_shared<NetworkManagerObject>(objectPath));
}

void NetworkDService::addVLANInterfaceObject(
    const std::string& objectPath, const VLANProperties& vLanVals,
    const EthernetInterfaceProperties& ethIfacevals)
{
    addObject(std::make_shared<VLANInterfaceObject>(objectPath, vLanVals,
                                                    ethIfacevals));
}

SystemConfigurationObject& NetworkDService::getSysConfObject(std::string path)
{
    return *(
        std::dynamic_pointer_cast<SystemConfigurationObject>(objectRepo[path]));
}

EthernetInterfaceObject& NetworkDService::getEtherIfaceObject(std::string path)
{
    return *(
        std::dynamic_pointer_cast<EthernetInterfaceObject>(objectRepo[path]));
}

NetworkManagerObject& NetworkDService::getNetworkManagerObject(std::string path)
{
    return *(std::dynamic_pointer_cast<NetworkManagerObject>(objectRepo[path]));
}

VLANInterfaceObject& NetworkDService::getVLANInterfaceObject(std::string path)
{
    return *(std::dynamic_pointer_cast<VLANInterfaceObject>(objectRepo[path]));
}
