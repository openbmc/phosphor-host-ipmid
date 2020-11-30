#include "ipmid_test.hpp"

#include <chrono>
#include <sdbusplus/sdbus.hpp>

#include <gtest/gtest.h>

using ::testing::Return;

using namespace std::literals::chrono_literals;
static const auto secondsToRunTest = 5s;
static const auto uSecondsToRunTest =
    std::chrono::microseconds(secondsToRunTest);

static constexpr char defaultNetworkDServiceName[] =
    "xyz.openbmc_project.Network";
static constexpr char defaultRestrictionModeServiceName[] =
    "xyz.openbmc_project.Control.Security.RestrictionMode";

static constexpr char defaultNetworkManagerObject[] =
    "/xyz/openbmc_project/network";
static constexpr char defaultSystemConfigurationObjPath[] =
    "/xyz/openbmc_project/network/config";
static constexpr char defaultEthernetInterfaceObjPath[] =
    "/xyz/openbmc_project/network/IPMB";

static constexpr char defaultRestrictionModeObjPath[] = "/";

static VLANProperties defaultVLANVals{{"interfaceName", ""},
                                      {"id", uint32_t(0)}};
static EthernetInterfaceProperties defaultVLANEthIfaceVals{
    {"InterfaceName", "eth1"},
    {"Speed", uint32_t(100)},
    {"AutoNeg", false},
    {"DomainName", std::vector<std::string>{"eth1.openbmc_project.xyz"}},
    {"DHCPEnabled", MockEthernetInterface::DHCPConf::none},
    {"Nameservers", std::vector<std::string>{"192.168.0.1"}},
    {"StaticNameServers", std::vector<std::string>{"192.168.0.1"}},
    {"NTPServers", std::vector<std::string>{"192.168.0.1"}},
    {"LinkLocalAutoConf", MockEthernetInterface::LinkLocalConf::both},
    {"IPv6AcceptRA", true},
    {"NICEnabled", true},
    {"LinkUp", true},
    {"DefaultGateway", "192.168.0.254"},
    {"DefaultGateway6", "aaaa::1234:1234:1234:1234"},
};

static const SystemConfigurationProperties defaultSystemConfigurationVals{
    {"HostName", "openbmc_project.xyz"},
    {"DefaultGateway", "192.168.0.1"},
    {"DefaultGateway6", "aaaa::1234:1234:1234:1234"}};

static const EthernetInterfaceProperties defaultEthernetInterfaceVals{
    {"InterfaceName", "eth0"},
    {"Speed", uint32_t(100)},
    {"AutoNeg", false},
    {"DomainName", std::vector<std::string>{"eth0.openbmc_project.xyz"}},
    {"DHCPEnabled", MockEthernetInterface::DHCPConf::none},
    {"Nameservers", std::vector<std::string>{"192.168.0.1"}},
    {"StaticNameServers", std::vector<std::string>{"192.168.0.1"}},
    {"NTPServers", std::vector<std::string>{"192.168.0.1"}},
    {"LinkLocalAutoConf", MockEthernetInterface::LinkLocalConf::both},
    {"IPv6AcceptRA", true},
    {"NICEnabled", true},
    {"LinkUp", true},
    {"DefaultGateway", "192.168.0.254"},
    {"DefaultGateway6", "aaaa::1234:1234:1234:1234"},
};

static const RestrictionModeProperties defaultRestrictionModeVals{
    {"RestrictionMode", MockRestrictionMode::Modes::None}};

static auto ipV4ToString(const uint8_t* ip)
{
    return std::to_string(ip[0]) + "." + std::to_string(ip[1]) + "." +
           std::to_string(ip[2]) + "." + std::to_string(ip[3]);
}

TEST(HostIpmiCommands, NetworkDIPTest)
{
    const uint8_t ipParam = 0x03;
    const uint8_t ipV4Test[] = {192, 168, 0, 27};
    const uint8_t prefixLength = 32;
    const std::string gateway = "";
    const std::vector<uint8_t> commandData{
        0, ipParam, ipV4Test[0], ipV4Test[1], ipV4Test[2], ipV4Test[3]};
    IpmidTest test;

    test.initiateRestrictionModeService(defaultRestrictionModeServiceName,
                                        uSecondsToRunTest);
    test.initiateNetworkDService(defaultNetworkDServiceName, uSecondsToRunTest);

    test.addNewRestrictionModeObject(defaultRestrictionModeObjPath,
                                     defaultRestrictionModeVals);

    test.addNewSystemConfigurationObject(defaultSystemConfigurationObjPath,
                                         defaultSystemConfigurationVals);
    test.addNewEthernetInterfaceObject(defaultEthernetInterfaceObjPath,
                                       defaultEthernetInterfaceVals);

    test.startRestrictionModeService();
    test.startNetworkDService();

    test.startIpmid();

    auto mockObjPtr = test.networkDService
                          ->getEtherIfaceObject(defaultEthernetInterfaceObjPath)
                          .getMockBase();
    EXPECT_CALL(*mockObjPtr, iP(MockIP::Protocol::IPv4, ipV4ToString(ipV4Test),
                                prefixLength, gateway))
        .WillOnce(
            Return(sdbusplus::message::object_path("/A/Fake/IP/Object/Path")));

    auto response = test.executeSetLan(commandData);

    response->verify();
}

TEST(HostIpmiCommands, NetworkDMacTest)
{
    const uint8_t macParam = 0x05;
    const uint8_t macAddrTest[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    const std::vector<uint8_t> commandData{0,
                                           macParam,
                                           macAddrTest[0],
                                           macAddrTest[1],
                                           macAddrTest[2],
                                           macAddrTest[3],
                                           macAddrTest[4],
                                           macAddrTest[5]};
    const auto expectedMacAddress = "aa:bb:cc:dd:ee:ff";
    IpmidTest test;

    test.initiateRestrictionModeService(defaultRestrictionModeServiceName,
                                        uSecondsToRunTest);
    test.initiateNetworkDService(defaultNetworkDServiceName, uSecondsToRunTest);

    test.addNewRestrictionModeObject(defaultRestrictionModeObjPath,
                                     defaultRestrictionModeVals);

    test.addNewSystemConfigurationObject(defaultSystemConfigurationObjPath,
                                         defaultSystemConfigurationVals);
    test.addNewEthernetInterfaceObject(defaultEthernetInterfaceObjPath,
                                       defaultEthernetInterfaceVals);

    test.startRestrictionModeService();
    test.startNetworkDService();

    test.startIpmid();

    auto mockObjPtr = test.networkDService
                          ->getEtherIfaceObject(defaultEthernetInterfaceObjPath)
                          .getMockBase();
    EXPECT_CALL(*mockObjPtr, mACAddress(expectedMacAddress))
        .WillOnce(Return(expectedMacAddress));

    auto response = test.executeSetLan(commandData);

    response->verify();
}

TEST(HostIpmiCommands, NetworkDGatewayAddressTest)
{
    const uint8_t gwParam = 0x0c;
    const uint8_t gwAddrTest[] = {192, 168, 0, 1};
    const std::vector<uint8_t> commandData{
        0, gwParam, gwAddrTest[0], gwAddrTest[1], gwAddrTest[2], gwAddrTest[3]};
    IpmidTest test;

    test.initiateRestrictionModeService(defaultRestrictionModeServiceName,
                                        uSecondsToRunTest);
    test.initiateNetworkDService(defaultNetworkDServiceName, uSecondsToRunTest);

    test.addNewRestrictionModeObject(defaultRestrictionModeObjPath,
                                     defaultRestrictionModeVals);

    test.addNewSystemConfigurationObject(defaultSystemConfigurationObjPath,
                                         defaultSystemConfigurationVals);
    test.addNewEthernetInterfaceObject(defaultEthernetInterfaceObjPath,
                                       defaultEthernetInterfaceVals);

    test.startRestrictionModeService();
    test.startNetworkDService();

    test.startIpmid();

    auto mockObjPtr = test.networkDService
                          ->getSysConfObject(defaultSystemConfigurationObjPath)
                          .getMockBase();
    EXPECT_CALL(*mockObjPtr, defaultGateway(ipV4ToString(gwAddrTest)))
        .WillOnce(Return(ipV4ToString(gwAddrTest)));

    auto response = test.executeSetLan(commandData);

    response->verify();
}

TEST(HostIpmiCommands, NetworkDGatewayMacAddressTest)
{
    const uint8_t gwMacParam = 0x0d;
    const uint8_t gwMacAddrTest[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    const std::vector<uint8_t> commandData{0,
                                           gwMacParam,
                                           gwMacAddrTest[0],
                                           gwMacAddrTest[1],
                                           gwMacAddrTest[2],
                                           gwMacAddrTest[3],
                                           gwMacAddrTest[4],
                                           gwMacAddrTest[5]};
    const auto expectedGatewayMacAddress = "11:22:33:44:55:66";
    IpmidTest test;

    test.initiateRestrictionModeService(defaultRestrictionModeServiceName,
                                        uSecondsToRunTest);
    test.initiateNetworkDService(defaultNetworkDServiceName, uSecondsToRunTest);

    test.addNewRestrictionModeObject(defaultRestrictionModeObjPath,
                                     defaultRestrictionModeVals);

    test.addNewSystemConfigurationObject(defaultSystemConfigurationObjPath,
                                         defaultSystemConfigurationVals);
    test.addNewEthernetInterfaceObject(defaultEthernetInterfaceObjPath,
                                       defaultEthernetInterfaceVals);

    test.startRestrictionModeService();
    test.startNetworkDService();

    test.startIpmid();

    auto mockObjPtr = test.networkDService
                          ->getEtherIfaceObject(defaultEthernetInterfaceObjPath)
                          .getMockBase();

    auto expectedGatewayIP =
        test.networkDService
            ->getSysConfObject(defaultSystemConfigurationObjPath)
            .getMockBase()
            ->defaultGateway();

    EXPECT_CALL(*mockObjPtr,
                neighbor(expectedGatewayIP, expectedGatewayMacAddress))
        .WillOnce(Return(
            sdbusplus::message::object_path("/A/Fake/Neighbor/Object/Path")));

    auto response = test.executeSetLan(commandData);

    response->verify();
}

TEST(HostIpmiCommands, NetworkDVLANCreateTest)
{
    const uint8_t vLanParam = 0x14;
    const std::vector<uint8_t> commandData{0, vLanParam, 0xff, 0b10001001};
    auto expectedInterfaceName = "IPMB";
    uint32_t expectedId = 2559;
    IpmidTest test;

    test.initiateRestrictionModeService(defaultRestrictionModeServiceName,
                                        uSecondsToRunTest);
    test.initiateNetworkDService(defaultNetworkDServiceName, uSecondsToRunTest);

    test.addNewRestrictionModeObject(defaultRestrictionModeObjPath,
                                     defaultRestrictionModeVals);

    test.addNewSystemConfigurationObject(defaultSystemConfigurationObjPath,
                                         defaultSystemConfigurationVals);
    test.addNewEthernetInterfaceObject(defaultEthernetInterfaceObjPath,
                                       defaultEthernetInterfaceVals);
    test.addNewNetworkManagerObject(defaultNetworkManagerObject);

    test.startRestrictionModeService();
    test.startNetworkDService();

    test.startIpmid();

    auto mockObjPtr = test.networkDService
                          ->getNetworkManagerObject(defaultNetworkManagerObject)
                          .getMockBase();
    EXPECT_CALL(*mockObjPtr, vLAN(expectedInterfaceName, expectedId))
        .WillOnce([&test](std::string interface, uint32_t id) {
            defaultVLANVals["interfaceName"] =
                interface + "." + std::to_string(id);
            defaultVLANVals["id"] = id;
            auto path = std::string(defaultNetworkManagerObject) + "/" +
                        interface + "_" + std::to_string(id);
            test.networkDService->addVLANInterfaceObject(
                path, defaultVLANVals, defaultVLANEthIfaceVals);
            return sdbusplus::message::object_path(path);
        });

    auto response = test.executeSetLan(commandData);

    response->verify();
}
