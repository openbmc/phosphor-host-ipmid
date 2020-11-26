#pragma once

#include <chrono>
#include <map>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server.hpp>
#include <sdbusplus/test/integration/mock_object.hpp>
#include <sdbusplus/test/integration/mock_service.hpp>
#include <sdbusplus/test/integration/private_bus.hpp>
#include <string>
#include <xyz/openbmc_project/Network/EthernetInterface/mock_server.hpp>
#include <xyz/openbmc_project/Network/IP/Create/mock_server.hpp>
#include <xyz/openbmc_project/Network/IP/mock_server.hpp>
#include <xyz/openbmc_project/Network/MACAddress/mock_server.hpp>
#include <xyz/openbmc_project/Network/Neighbor/CreateStatic/mock_server.hpp>
#include <xyz/openbmc_project/Network/SystemConfiguration/mock_server.hpp>
#include <xyz/openbmc_project/Network/VLAN/Create/mock_server.hpp>
#include <xyz/openbmc_project/Network/VLAN/mock_server.hpp>

using sdbusplus::SdBusDuration;
using sdbusplus::test::integration::MockObject;
using sdbusplus::test::integration::MockService;
using sdbusplus::test::integration::PrivateBus;

using sdbusplus::xyz::openbmc_project::Network::IP::server::MockCreate;
using sdbusplus::xyz::openbmc_project::Network::Neighbor::server::
    MockCreateStatic;
using sdbusplus::xyz::openbmc_project::Network::server::MockEthernetInterface;
using sdbusplus::xyz::openbmc_project::Network::server::MockIP;
using sdbusplus::xyz::openbmc_project::Network::server::MockMACAddress;
using sdbusplus::xyz::openbmc_project::Network::server::MockSystemConfiguration;
using sdbusplus::xyz::openbmc_project::Network::server::MockVLAN;
using MockVLANCreate =
    sdbusplus::xyz::openbmc_project::Network::VLAN::server::MockCreate;

/** The list of mock interfaces is passed as the template parameter
 * to these objects.
 */
using MockSystemConfigurationObjectBase =
    sdbusplus::server::object_t<MockSystemConfiguration>;
using MockEthernetInterfaceObjectBase =
    sdbusplus::server::object_t<MockEthernetInterface, MockCreate,
                                MockMACAddress, MockCreateStatic>;
using MockNetworkManagerObjectBase =
    sdbusplus::server::object_t<MockVLANCreate>;
using MockVLANObjectBase =
    sdbusplus::server::object_t<MockVLAN, MockEthernetInterface>;

using SystemConfigurationProperties =
    std::map<std::string, MockSystemConfiguration::PropertiesVariant>;
using EthernetInterfaceProperties =
    std::map<std::string, MockEthernetInterface::PropertiesVariant>;
using VLANProperties = std::map<std::string, MockVLAN::PropertiesVariant>;

class NetworkManagerObject : public MockObject
{
  public:
    /** Constructs a NetworkManager object.
     * @see NetworkDService.addNetworkManagerObject()
     */
    NetworkManagerObject(const std::string& path);

    /** Overrides the start method in base class to initialize the
     * mockBase object.
     */
    void start(sdbusplus::bus::bus& bus) override;

    std::shared_ptr<MockNetworkManagerObjectBase> getMockBase();

  private:
    /** The reference to sdbusplus object that implements the mock interface.
     */
    std::shared_ptr<MockNetworkManagerObjectBase> mockBase;
};

class EthernetInterfaceObject : public MockObject
{
  public:
    /** Constructs a EthernetInterface object.
     * @see NetworkDService.addEthernetInterfaceObject()
     */
    EthernetInterfaceObject(const std::string& path,
                            const EthernetInterfaceProperties& ethIfaceVals);

    /** Overrides the start method in base class to initialize the
     * mockBase object.
     */
    void start(sdbusplus::bus::bus& bus) override;

    std::shared_ptr<MockEthernetInterfaceObjectBase> getMockBase();

  private:
    const EthernetInterfaceProperties& initialEthIfaceVals;
    /** The reference to sdbusplus object that implements the mock interface.
     */
    std::shared_ptr<MockEthernetInterfaceObjectBase> mockBase;
};

class VLANInterfaceObject : public MockObject
{
  public:
    /** Constructs a VLANInterface object.
     * @see NetworkDService.addVLANInterfaceObject()
     */
    VLANInterfaceObject(const std::string& path, const VLANProperties& vLanVals,
                        const EthernetInterfaceProperties& ethIfaceVals);
    /** Overrides the start method in base class to initialize the
     * mockBase object.
     */
    void start(sdbusplus::bus::bus& bus) override;

    std::shared_ptr<MockVLANObjectBase> getMockBase();

  private:
    const VLANProperties& initialVLanVals;
    const EthernetInterfaceProperties& initialEthIfaceVals;
    /** The reference to sdbusplus object that implements the mock interface.
     */
    std::shared_ptr<MockVLANObjectBase> mockBase;
};

class SystemConfigurationObject : public MockObject
{
  public:
    /** Constructs a SystemConfiguration object.
     * @see NetworkDService.addSystemConfigurationObject()
     */
    SystemConfigurationObject(const std::string& path,
                              const SystemConfigurationProperties& sysConfVals);
    /** Overrides the start method in base class to initialize the
     * mockBase object.
     */
    void start(sdbusplus::bus::bus& bus) override;

    std::shared_ptr<MockSystemConfigurationObjectBase> getMockBase();

  private:
    const SystemConfigurationProperties& initialSysConfVals;
    /** The reference to sdbusplus object that implements the mock interface.
     */
    std::shared_ptr<MockSystemConfigurationObjectBase> mockBase;
};

/** This service and its associated objects are intended to mock some behaviors
 * of OpenBMC daemon named networkd. It implements network.SystemConfiguration,
 * network.EthernetInterface, network.IP, and network.IP.Create interfaces.
 */
class NetworkDService : public MockService
{
  public:
    NetworkDService(std::string name, std::shared_ptr<PrivateBus> privateBus,
                    SdBusDuration microsecondsToRun);

    /** Adds a new SystemConfiguration object to this service.
     *
     * @param objectPath - The path of the object on D-Bus.
     * @param sysConfVals - initial interface values.
     */
    void addSystemConfigurationObject(
        const std::string& objectPath,
        const SystemConfigurationProperties& sysConfVals);
    /** Adds a new EthernetInterface object to this service.
     *
     * @param objectPath - The path of the object on D-Bus.
     * @param ethIfacevals - initial interface values.
     */
    void addEthernetInterfaceObject(
        const std::string& objectPath,
        const EthernetInterfaceProperties& ethIfacevals);
    /** Adds a new SystemConfiguration object to this service.
     *
     * @param objectPath - The path of the object on D-Bus.
     */
    void addNetworkManagerObject(const std::string& objectPath);
    /** Adds a new VLANInterface object to this service.
     *
     * @param objectPath - The path of the object on D-Bus.
     * @param vLanVals - initial interface values for vlan.
     * @param ethIfacevals - initial interface values for eth interface.
     */
    void
        addVLANInterfaceObject(const std::string& objectPath,
                               const VLANProperties& vLanVals,
                               const EthernetInterfaceProperties& ethIfacevals);

    SystemConfigurationObject& getSysConfObject(std::string path);

    EthernetInterfaceObject& getEtherIfaceObject(std::string path);

    NetworkManagerObject& getNetworkManagerObject(std::string path);

    VLANInterfaceObject& getVLANInterfaceObject(std::string path);
};
