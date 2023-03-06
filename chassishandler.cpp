#include "config.h"

#include "chassishandler.hpp"

#include <arpa/inet.h>
#include <endian.h>
#include <limits.h>
#include <mapper.h>
#include <netinet/in.h>

#include <array>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <future>
#include <ipmid/api.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <map>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/message/types.hpp>
#include <sdbusplus/server/object.hpp>
#include <sdbusplus/timer.hpp>
#include <settings.hpp>
#include <sstream>
#include <string>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/Control/Boot/Mode/server.hpp>
#include <xyz/openbmc_project/Control/Boot/Source/server.hpp>
#include <xyz/openbmc_project/Control/Boot/Type/server.hpp>
#include <xyz/openbmc_project/Control/Power/RestorePolicy/server.hpp>
#include <xyz/openbmc_project/State/Chassis/server.hpp>
#include <xyz/openbmc_project/State/Host/server.hpp>
#include <xyz/openbmc_project/State/PowerOnHours/server.hpp>

std::unique_ptr<phosphor::Timer> identifyTimer
    __attribute__((init_priority(101)));

static ChassisIDState chassisIDState = ChassisIDState::reserved;
static constexpr uint8_t setParmVersion = 0x01;

constexpr size_t sizeVersion = 2;
constexpr size_t DEFAULT_IDENTIFY_TIME_OUT = 15;

// PetiBoot-Specific
static constexpr uint8_t netConfInitialBytes[] = {0x80, 0x21, 0x70, 0x62,
                                                  0x21, 0x00, 0x01, 0x06};
static constexpr uint8_t oemParmStart = 96;
static constexpr uint8_t oemParmEnd = 127;

static constexpr size_t cookieOffset = 1;
static constexpr size_t versionOffset = 5;
static constexpr size_t addrSizeOffset = 8;
static constexpr size_t macOffset = 9;
static constexpr size_t addrTypeOffset = 16;
static constexpr size_t ipAddrOffset = 17;

static constexpr size_t encIdentifyObjectsSize = 1;
static constexpr size_t chassisIdentifyReqLength = 2;
static constexpr size_t identifyIntervalPos = 0;
static constexpr size_t forceIdentifyPos = 1;

namespace ipmi
{
constexpr Cc ccParmNotSupported = 0x80;

static inline auto responseParmNotSupported()
{
    return response(ccParmNotSupported);
}
} // namespace ipmi

void register_netfn_chassis_functions() __attribute__((constructor));

// Host settings in dbus
// Service name should be referenced by connection name got via object mapper
const char* settings_object_name = "/org/openbmc/settings/host0";
const char* settings_intf_name = "org.freedesktop.DBus.Properties";
const char* identify_led_object_name =
    "/xyz/openbmc_project/led/groups/enclosure_identify";

constexpr auto SETTINGS_ROOT = "/";
constexpr auto SETTINGS_MATCH = "host0";

constexpr auto IP_INTERFACE = "xyz.openbmc_project.Network.IP";
constexpr auto MAC_INTERFACE = "xyz.openbmc_project.Network.MACAddress";

static constexpr auto chassisStateRoot = "/xyz/openbmc_project/state";
static constexpr auto chassisPOHStateIntf =
    "xyz.openbmc_project.State.PowerOnHours";
static constexpr auto pohCounterProperty = "POHCounter";
static constexpr auto match = "chassis0";
const static constexpr char chassisCapIntf[] =
    "xyz.openbmc_project.Control.ChassisCapabilities";
const static constexpr char chassisIntrusionProp[] = "ChassisIntrusionEnabled";
const static constexpr char chassisFrontPanelLockoutProp[] =
    "ChassisFrontPanelLockoutEnabled";
const static constexpr char chassisNMIProp[] = "ChassisNMIEnabled";
const static constexpr char chassisPowerInterlockProp[] =
    "ChassisPowerInterlockEnabled";
const static constexpr char chassisFRUDevAddrProp[] = "FRUDeviceAddress";
const static constexpr char chassisSDRDevAddrProp[] = "SDRDeviceAddress";
const static constexpr char chassisSELDevAddrProp[] = "SELDeviceAddress";
const static constexpr char chassisSMDevAddrProp[] = "SMDeviceAddress";
const static constexpr char chassisBridgeDevAddrProp[] = "BridgeDeviceAddress";
static constexpr uint8_t chassisCapFlagMask = 0x0f;
static constexpr uint8_t chassisCapAddrMask = 0xfe;
static constexpr const char* powerButtonIntf =
    "xyz.openbmc_project.Chassis.Buttons.Power";
static constexpr const char* powerButtonPath =
    "/xyz/openbmc_project/Chassis/Buttons/Power0";
static constexpr const char* resetButtonIntf =
    "xyz.openbmc_project.Chassis.Buttons.Reset";
static constexpr const char* resetButtonPath =
    "/xyz/openbmc_project/Chassis/Buttons/Reset0";

// Phosphor Host State manager
namespace State = sdbusplus::xyz::openbmc_project::State::server;

namespace fs = std::filesystem;

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using namespace sdbusplus::xyz::openbmc_project::Control::Boot::server;

namespace chassis
{
namespace internal
{

constexpr auto bootSettingsPath = "/xyz/openbmc_project/control/host0/boot";
constexpr auto bootEnableIntf = "xyz.openbmc_project.Object.Enable";
constexpr auto bootModeIntf = "xyz.openbmc_project.Control.Boot.Mode";
constexpr auto bootTypeIntf = "xyz.openbmc_project.Control.Boot.Type";
constexpr auto bootSourceIntf = "xyz.openbmc_project.Control.Boot.Source";
constexpr auto bootSettingsOneTimePath =
    "/xyz/openbmc_project/control/host0/boot/one_time";
constexpr auto bootOneTimeIntf = "xyz.openbmc_project.Object.Enable";

constexpr auto powerRestoreIntf =
    "xyz.openbmc_project.Control.Power.RestorePolicy";
sdbusplus::bus_t dbus(ipmid_get_sd_bus_connection());

namespace cache
{

std::unique_ptr<settings::Objects> objectsPtr = nullptr;

settings::Objects& getObjects()
{
    if (objectsPtr == nullptr)
    {
        objectsPtr = std::make_unique<settings::Objects>(
            dbus, std::vector<std::string>{bootModeIntf, bootTypeIntf,
                                           bootSourceIntf, powerRestoreIntf});
    }
    return *objectsPtr;
}

} // namespace cache
} // namespace internal
} // namespace chassis

namespace poh
{

constexpr auto minutesPerCount = 60;

} // namespace poh

int getHostNetworkData(ipmi::message::Payload& payload)
{
    ipmi::PropertyMap properties;
    int rc = 0;
    uint8_t addrSize = ipmi::network::IPV4_ADDRESS_SIZE_BYTE;

    try
    {
        // TODO There may be cases where an interface is implemented by multiple
        // objects,to handle such cases we are interested on that object
        //  which are on interested busname.
        //  Currenlty mapper doesn't give the readable busname(gives busid)
        //  so we can't match with bus name so giving some object specific info
        //  as SETTINGS_MATCH.
        //  Later SETTINGS_MATCH will be replaced with busname.

        sdbusplus::bus_t bus(ipmid_get_sd_bus_connection());

        auto ipObjectInfo = ipmi::getDbusObject(bus, IP_INTERFACE,
                                                SETTINGS_ROOT, SETTINGS_MATCH);

        auto macObjectInfo = ipmi::getDbusObject(bus, MAC_INTERFACE,
                                                 SETTINGS_ROOT, SETTINGS_MATCH);

        properties = ipmi::getAllDbusProperties(
            bus, ipObjectInfo.second, ipObjectInfo.first, IP_INTERFACE);
        auto variant = ipmi::getDbusProperty(bus, macObjectInfo.second,
                                             macObjectInfo.first, MAC_INTERFACE,
                                             "MACAddress");

        auto ipAddress = std::get<std::string>(properties["Address"]);

        auto gateway = std::get<std::string>(properties["Gateway"]);

        auto prefix = std::get<uint8_t>(properties["PrefixLength"]);

        uint8_t isStatic =
            (std::get<std::string>(properties["Origin"]) ==
             "xyz.openbmc_project.Network.IP.AddressOrigin.Static")
                ? 1
                : 0;

        auto MACAddress = std::get<std::string>(variant);

        // it is expected here that we should get the valid data
        // but we may also get the default values.
        // Validation of the data is done by settings.
        //
        // if mac address is default mac address then
        // don't send blank override.
        if ((MACAddress == ipmi::network::DEFAULT_MAC_ADDRESS))
        {
            rc = -1;
            return rc;
        }
        // if addr is static then ipaddress,gateway,prefix
        // should not be default one,don't send blank override.
        if (isStatic)
        {
            if ((ipAddress == ipmi::network::DEFAULT_ADDRESS) ||
                (gateway == ipmi::network::DEFAULT_ADDRESS) || (!prefix))
            {
                rc = -1;
                return rc;
            }
        }

        std::string token;
        std::stringstream ss(MACAddress);

        // First pack macOffset no of bytes in payload.
        // Latter this PetiBoot-Specific data will be populated.
        std::vector<uint8_t> payloadInitialBytes(macOffset);
        payload.pack(payloadInitialBytes);

        while (std::getline(ss, token, ':'))
        {
            payload.pack(stoi(token, nullptr, 16));
        }

        payload.pack(0x00);

        payload.pack(isStatic);

        uint8_t addressFamily = (std::get<std::string>(properties["Type"]) ==
                                 "xyz.openbmc_project.Network.IP.Protocol.IPv4")
                                    ? AF_INET
                                    : AF_INET6;

        addrSize = (addressFamily == AF_INET)
                       ? ipmi::network::IPV4_ADDRESS_SIZE_BYTE
                       : ipmi::network::IPV6_ADDRESS_SIZE_BYTE;

        // ipaddress and gateway would be in IPv4 format
        std::vector<uint8_t> addrInBinary(addrSize);
        inet_pton(addressFamily, ipAddress.c_str(),
                  reinterpret_cast<void*>(addrInBinary.data()));

        payload.pack(addrInBinary);

        payload.pack(prefix);

        std::vector<uint8_t> gatewayDetails(addrSize);
        inet_pton(addressFamily, gateway.c_str(),
                  reinterpret_cast<void*>(gatewayDetails.data()));
        payload.pack(gatewayDetails);
    }
    catch (const InternalFailure& e)
    {
        commit<InternalFailure>();
        rc = -1;
        return rc;
    }

    // PetiBoot-Specific
    // If success then copy the first 9 bytes to the payload message
    // payload first 2 bytes contain the parameter values. Skip that 2 bytes.
    uint8_t skipFirstTwoBytes = 2;
    size_t payloadSize = payload.size();
    uint8_t* configDataStartingAddress = payload.data() + skipFirstTwoBytes;

    if (payloadSize < skipFirstTwoBytes + sizeof(netConfInitialBytes))
    {
        log<level::ERR>("Invalid net config ");
        rc = -1;
        return rc;
    }
    std::copy(netConfInitialBytes,
              netConfInitialBytes + sizeof(netConfInitialBytes),
              configDataStartingAddress);

    if (payloadSize < skipFirstTwoBytes + addrSizeOffset + sizeof(addrSize))
    {
        log<level::ERR>("Invalid length of address size");
        rc = -1;
        return rc;
    }
    std::copy(&addrSize, &(addrSize) + sizeof(addrSize),
              configDataStartingAddress + addrSizeOffset);

#ifdef _IPMI_DEBUG_
    std::printf("\n===Printing the IPMI Formatted Data========\n");

    for (uint8_t pos = 0; pos < index; pos++)
    {
        std::printf("%02x ", payloadStartingAddress[pos]);
    }
#endif

    return rc;
}

/** @brief convert IPv4 and IPv6 addresses from binary to text form.
 *  @param[in] family - IPv4/Ipv6
 *  @param[in] data - req data pointer.
 *  @param[in] offset - offset in the data.
 *  @param[in] addrSize - size of the data which needs to be read from offset.
 *  @returns address in text form.
 */

std::string getAddrStr(uint8_t family, uint8_t* data, uint8_t offset,
                       uint8_t addrSize)
{
    char ipAddr[INET6_ADDRSTRLEN] = {};

    switch (family)
    {
        case AF_INET:
        {
            struct sockaddr_in addr4
            {
            };
            std::memcpy(&addr4.sin_addr.s_addr, &data[offset], addrSize);

            inet_ntop(AF_INET, &addr4.sin_addr, ipAddr, INET_ADDRSTRLEN);

            break;
        }
        case AF_INET6:
        {
            struct sockaddr_in6 addr6
            {
            };
            std::memcpy(&addr6.sin6_addr.s6_addr, &data[offset], addrSize);

            inet_ntop(AF_INET6, &addr6.sin6_addr, ipAddr, INET6_ADDRSTRLEN);

            break;
        }
        default:
        {
            return {};
        }
    }

    return ipAddr;
}

ipmi::Cc setHostNetworkData(ipmi::message::Payload& data)
{
    using namespace std::string_literals;
    std::string hostNetworkConfig;
    std::string mac("00:00:00:00:00:00");
    std::string ipAddress, gateway;
    std::string addrOrigin{0};
    uint8_t addrSize{0};
    std::string addressOrigin =
        "xyz.openbmc_project.Network.IP.AddressOrigin.DHCP";
    std::string addressType = "xyz.openbmc_project.Network.IP.Protocol.IPv4";
    uint8_t prefix{0};
    uint8_t family = AF_INET;

    // cookie starts from second byte
    // version starts from sixth byte

    try
    {
        do
        {
            // cookie ==  0x21 0x70 0x62 0x21
            data.trailingOk = true;
            auto msgLen = data.size();
            std::vector<uint8_t> msgPayloadBytes(msgLen);
            if (data.unpack(msgPayloadBytes) != 0 || !data.fullyUnpacked())
            {
                log<level::ERR>(
                    "Error in unpacking message of setHostNetworkData");
                return ipmi::ccReqDataLenInvalid;
            }

            uint8_t* msgPayloadStartingPos = msgPayloadBytes.data();
            constexpr size_t cookieSize = 4;
            if (msgLen < cookieOffset + cookieSize)
            {
                log<level::ERR>(
                    "Error in cookie getting of setHostNetworkData");
                return ipmi::ccReqDataLenInvalid;
            }
            if (std::equal(msgPayloadStartingPos + cookieOffset,
                           msgPayloadStartingPos + cookieOffset + cookieSize,
                           (netConfInitialBytes + cookieOffset)) != 0)
            {
                // all cookie == 0
                if (std::all_of(msgPayloadStartingPos + cookieOffset,
                                msgPayloadStartingPos + cookieOffset +
                                    cookieSize,
                                [](int i) { return i == 0; }) == true)
                {
                    // need to zero out the network settings.
                    break;
                }

                log<level::ERR>("Invalid Cookie");
                elog<InternalFailure>();
            }

            // vesion == 0x00 0x01
            if (msgLen < versionOffset + sizeVersion)
            {
                log<level::ERR>(
                    "Error in version getting of setHostNetworkData");
                return ipmi::ccReqDataLenInvalid;
            }
            if (std::equal(msgPayloadStartingPos + versionOffset,
                           msgPayloadStartingPos + versionOffset + sizeVersion,
                           (netConfInitialBytes + versionOffset)) != 0)
            {
                log<level::ERR>("Invalid Version");
                elog<InternalFailure>();
            }

            if (msgLen < macOffset + 6)
            {
                log<level::ERR>(
                    "Error in mac address getting of setHostNetworkData");
                return ipmi::ccReqDataLenInvalid;
            }
            std::stringstream result;
            std::copy((msgPayloadStartingPos + macOffset),
                      (msgPayloadStartingPos + macOffset + 5),
                      std::ostream_iterator<int>(result, ":"));
            mac = result.str();

            if (msgLen < addrTypeOffset + sizeof(decltype(addrOrigin)))
            {
                log<level::ERR>(
                    "Error in original address getting of setHostNetworkData");
                return ipmi::ccReqDataLenInvalid;
            }
            std::copy(msgPayloadStartingPos + addrTypeOffset,
                      msgPayloadStartingPos + addrTypeOffset +
                          sizeof(decltype(addrOrigin)),
                      std::ostream_iterator<int>(result, ""));
            addrOrigin = result.str();

            if (!addrOrigin.empty())
            {
                addressOrigin =
                    "xyz.openbmc_project.Network.IP.AddressOrigin.Static";
            }

            if (msgLen < addrSizeOffset + sizeof(decltype(addrSize)))
            {
                log<level::ERR>(
                    "Error in address size getting of setHostNetworkData");
                return ipmi::ccReqDataLenInvalid;
            }
            // Get the address size
            std::copy(msgPayloadStartingPos + addrSizeOffset,
                      (msgPayloadStartingPos + addrSizeOffset +
                       sizeof(decltype(addrSize))),
                      &addrSize);

            uint8_t prefixOffset = ipAddrOffset + addrSize;
            if (msgLen < prefixOffset + sizeof(decltype(prefix)))
            {
                log<level::ERR>(
                    "Error in prefix getting of setHostNetworkData");
                return ipmi::ccReqDataLenInvalid;
            }
            std::copy(msgPayloadStartingPos + prefixOffset,
                      (msgPayloadStartingPos + prefixOffset +
                       sizeof(decltype(prefix))),
                      &prefix);

            uint8_t gatewayOffset = prefixOffset + sizeof(decltype(prefix));
            if (addrSize != ipmi::network::IPV4_ADDRESS_SIZE_BYTE)
            {
                addressType = "xyz.openbmc_project.Network.IP.Protocol.IPv6";
                family = AF_INET6;
            }

            if (msgLen < ipAddrOffset + addrSize)
            {
                log<level::ERR>(
                    "Error in IP address getting of setHostNetworkData");
                return ipmi::ccReqDataLenInvalid;
            }
            ipAddress = getAddrStr(family, msgPayloadStartingPos, ipAddrOffset,
                                   addrSize);

            if (msgLen < gatewayOffset + addrSize)
            {
                log<level::ERR>(
                    "Error in gateway address getting of setHostNetworkData");
                return ipmi::ccReqDataLenInvalid;
            }
            gateway = getAddrStr(family, msgPayloadStartingPos, gatewayOffset,
                                 addrSize);

        } while (0);

        // Cookie == 0 or it is a valid cookie
        hostNetworkConfig += "ipaddress="s + ipAddress + ",prefix="s +
                             std::to_string(prefix) + ",gateway="s + gateway +
                             ",mac="s + mac + ",addressOrigin="s +
                             addressOrigin;

        sdbusplus::bus_t bus(ipmid_get_sd_bus_connection());

        auto ipObjectInfo = ipmi::getDbusObject(bus, IP_INTERFACE,
                                                SETTINGS_ROOT, SETTINGS_MATCH);
        auto macObjectInfo = ipmi::getDbusObject(bus, MAC_INTERFACE,
                                                 SETTINGS_ROOT, SETTINGS_MATCH);
        // set the dbus property
        ipmi::setDbusProperty(bus, ipObjectInfo.second, ipObjectInfo.first,
                              IP_INTERFACE, "Address", std::string(ipAddress));
        ipmi::setDbusProperty(bus, ipObjectInfo.second, ipObjectInfo.first,
                              IP_INTERFACE, "PrefixLength", prefix);
        ipmi::setDbusProperty(bus, ipObjectInfo.second, ipObjectInfo.first,
                              IP_INTERFACE, "Origin", addressOrigin);
        ipmi::setDbusProperty(bus, ipObjectInfo.second, ipObjectInfo.first,
                              IP_INTERFACE, "Gateway", std::string(gateway));
        ipmi::setDbusProperty(
            bus, ipObjectInfo.second, ipObjectInfo.first, IP_INTERFACE, "Type",
            std::string("xyz.openbmc_project.Network.IP.Protocol.IPv4"));
        ipmi::setDbusProperty(bus, macObjectInfo.second, macObjectInfo.first,
                              MAC_INTERFACE, "MACAddress", std::string(mac));

        log<level::DEBUG>("Network configuration changed",
                          entry("NETWORKCONFIG=%s", hostNetworkConfig.c_str()));
    }
    catch (const sdbusplus::exception_t& e)
    {
        commit<InternalFailure>();
        log<level::ERR>("Error in  ipmiChassisSetSysBootOptions call");
        return ipmi::ccUnspecifiedError;
    }

    return ipmi::ccSuccess;
}

uint32_t getPOHCounter()
{
    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};

    auto chassisStateObj =
        ipmi::getDbusObject(bus, chassisPOHStateIntf, chassisStateRoot, match);

    auto service =
        ipmi::getService(bus, chassisPOHStateIntf, chassisStateObj.first);

    auto propValue =
        ipmi::getDbusProperty(bus, service, chassisStateObj.first,
                              chassisPOHStateIntf, pohCounterProperty);

    return std::get<uint32_t>(propValue);
}

/** @brief Implements the get chassis capabilities command
 *
 *  @returns IPMI completion code plus response data
 *  chassisCapFlags        - chassis capability flag
 *  chassisFRUInfoDevAddr  - chassis FRU info Device Address
 *  chassisSDRDevAddr      - chassis SDR device address
 *  chassisSELDevAddr      - chassis SEL device address
 *  chassisSMDevAddr       - chassis system management device address
 *  chassisBridgeDevAddr   - chassis bridge device address
 */
ipmi::RspType<bool,    // chassis intrusion sensor
              bool,    // chassis Front panel lockout
              bool,    // chassis NMI
              bool,    // chassis power interlock
              uint4_t, // reserved
              uint8_t, // chassis FRU info Device Address
              uint8_t, // chassis SDR device address
              uint8_t, // chassis SEL device address
              uint8_t, // chassis system management device address
              uint8_t  // chassis bridge device address
              >
    ipmiGetChassisCap()
{
    ipmi::PropertyMap properties;
    try
    {
        sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};

        ipmi::DbusObjectInfo chassisCapObject =
            ipmi::getDbusObject(bus, chassisCapIntf);

        // capabilities flags
        // [7..4] - reserved
        // [3] – 1b = provides power interlock  (IPM 1.5)
        // [2] – 1b = provides Diagnostic Interrupt (FP NMI)
        // [1] – 1b = provides “Front Panel Lockout” (indicates that the chassis
        // has capabilities
        //            to lock out external power control and reset button or
        //            front panel interfaces and/or detect tampering with those
        //            interfaces).
        // [0] -1b = Chassis provides intrusion (physical security) sensor.
        // set to default value 0x0.

        properties =
            ipmi::getAllDbusProperties(bus, chassisCapObject.second,
                                       chassisCapObject.first, chassisCapIntf);
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("Failed to fetch Chassis Capability properties",
                        entry("ERROR=%s", e.what()));
        return ipmi::responseUnspecifiedError();
    }

    bool* chassisIntrusionFlag =
        std::get_if<bool>(&properties[chassisIntrusionProp]);
    if (chassisIntrusionFlag == nullptr)
    {
        log<level::ERR>("Error to get chassis Intrusion flags");
        return ipmi::responseUnspecifiedError();
    }
    bool* chassisFrontPanelFlag =
        std::get_if<bool>(&properties[chassisFrontPanelLockoutProp]);
    if (chassisFrontPanelFlag == nullptr)
    {
        log<level::ERR>("Error to get chassis intrusion flags");
        return ipmi::responseUnspecifiedError();
    }
    bool* chassisNMIFlag = std::get_if<bool>(&properties[chassisNMIProp]);
    if (chassisNMIFlag == nullptr)
    {
        log<level::ERR>("Error to get chassis NMI flags");
        return ipmi::responseUnspecifiedError();
    }
    bool* chassisPowerInterlockFlag =
        std::get_if<bool>(&properties[chassisPowerInterlockProp]);
    if (chassisPowerInterlockFlag == nullptr)
    {
        log<level::ERR>("Error to get chassis power interlock flags");
        return ipmi::responseUnspecifiedError();
    }
    uint8_t* chassisFRUInfoDevAddr =
        std::get_if<uint8_t>(&properties[chassisFRUDevAddrProp]);
    if (chassisFRUInfoDevAddr == nullptr)
    {
        log<level::ERR>("Error to get chassis FRU info device address");
        return ipmi::responseUnspecifiedError();
    }
    uint8_t* chassisSDRDevAddr =
        std::get_if<uint8_t>(&properties[chassisSDRDevAddrProp]);
    if (chassisSDRDevAddr == nullptr)
    {
        log<level::ERR>("Error to get chassis SDR device address");
        return ipmi::responseUnspecifiedError();
    }
    uint8_t* chassisSELDevAddr =
        std::get_if<uint8_t>(&properties[chassisSELDevAddrProp]);
    if (chassisSELDevAddr == nullptr)
    {
        log<level::ERR>("Error to get chassis SEL device address");
        return ipmi::responseUnspecifiedError();
    }
    uint8_t* chassisSMDevAddr =
        std::get_if<uint8_t>(&properties[chassisSMDevAddrProp]);
    if (chassisSMDevAddr == nullptr)
    {
        log<level::ERR>("Error to get chassis SM device address");
        return ipmi::responseUnspecifiedError();
    }
    uint8_t* chassisBridgeDevAddr =
        std::get_if<uint8_t>(&properties[chassisBridgeDevAddrProp]);
    if (chassisBridgeDevAddr == nullptr)
    {
        log<level::ERR>("Error to get chassis bridge device address");
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(*chassisIntrusionFlag, *chassisFrontPanelFlag,
                                 *chassisNMIFlag, *chassisPowerInterlockFlag, 0,
                                 *chassisFRUInfoDevAddr, *chassisSDRDevAddr,
                                 *chassisSELDevAddr, *chassisSMDevAddr,
                                 *chassisBridgeDevAddr);
}

/** @brief implements set chassis capalibities command
 *  @param intrusion        - chassis intrusion
 *  @param fpLockout        - frontpannel lockout
 *  @param reserved1        - skip one bit
 *  @param fruDeviceAddr    - chassis FRU info Device Address
 *  @param sdrDeviceAddr    - chassis SDR device address
 *  @param selDeviceAddr    - chassis SEL device address
 *  @param smDeviceAddr     - chassis system management device address
 *  @param bridgeDeviceAddr - chassis bridge device address
 *
 *  @returns IPMI completion code
 */
ipmi::RspType<> ipmiSetChassisCap(bool intrusion, bool fpLockout,
                                  uint6_t reserved1,

                                  uint8_t fruDeviceAddr,

                                  uint8_t sdrDeviceAddr,

                                  uint8_t selDeviceAddr,

                                  uint8_t smDeviceAddr,

                                  uint8_t bridgeDeviceAddr)
{

    // check input data
    if (reserved1 != 0)
    {
        log<level::ERR>("Unsupported request parameter");
        return ipmi::responseInvalidFieldRequest();
    }

    if ((fruDeviceAddr & ~chassisCapAddrMask) != 0)
    {
        log<level::ERR>("Unsupported request parameter(FRU Addr)",
                        entry("REQ=0x%x", fruDeviceAddr));
        return ipmi::responseInvalidFieldRequest();
    }
    if ((sdrDeviceAddr & ~chassisCapAddrMask) != 0)
    {
        log<level::ERR>("Unsupported request parameter(SDR Addr)",
                        entry("REQ=0x%x", sdrDeviceAddr));
        return ipmi::responseInvalidFieldRequest();
    }

    if ((selDeviceAddr & ~chassisCapAddrMask) != 0)
    {
        log<level::ERR>("Unsupported request parameter(SEL Addr)",
                        entry("REQ=0x%x", selDeviceAddr));
        return ipmi::responseInvalidFieldRequest();
    }

    if ((smDeviceAddr & ~chassisCapAddrMask) != 0)
    {
        log<level::ERR>("Unsupported request parameter(SM Addr)",
                        entry("REQ=0x%x", smDeviceAddr));
        return ipmi::responseInvalidFieldRequest();
    }

    if ((bridgeDeviceAddr & ~chassisCapAddrMask) != 0)
    {
        log<level::ERR>("Unsupported request parameter(Bridge Addr)",
                        entry("REQ=0x%x", bridgeDeviceAddr));
        return ipmi::responseInvalidFieldRequest();
    }

    try
    {
        sdbusplus::bus_t bus(ipmid_get_sd_bus_connection());
        ipmi::DbusObjectInfo chassisCapObject =
            ipmi::getDbusObject(bus, chassisCapIntf);

        ipmi::setDbusProperty(bus, chassisCapObject.second,
                              chassisCapObject.first, chassisCapIntf,
                              chassisIntrusionProp, intrusion);

        ipmi::setDbusProperty(bus, chassisCapObject.second,
                              chassisCapObject.first, chassisCapIntf,
                              chassisFrontPanelLockoutProp, fpLockout);

        ipmi::setDbusProperty(bus, chassisCapObject.second,
                              chassisCapObject.first, chassisCapIntf,
                              chassisFRUDevAddrProp, fruDeviceAddr);

        ipmi::setDbusProperty(bus, chassisCapObject.second,
                              chassisCapObject.first, chassisCapIntf,
                              chassisSDRDevAddrProp, sdrDeviceAddr);

        ipmi::setDbusProperty(bus, chassisCapObject.second,
                              chassisCapObject.first, chassisCapIntf,
                              chassisSELDevAddrProp, selDeviceAddr);

        ipmi::setDbusProperty(bus, chassisCapObject.second,
                              chassisCapObject.first, chassisCapIntf,
                              chassisSMDevAddrProp, smDeviceAddr);

        ipmi::setDbusProperty(bus, chassisCapObject.second,
                              chassisCapObject.first, chassisCapIntf,
                              chassisBridgeDevAddrProp, bridgeDeviceAddr);
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(e.what());
        return ipmi::responseUnspecifiedError();
    }
    return ipmi::responseSuccess();
}

//------------------------------------------
// Calls into Host State Manager Dbus object
//------------------------------------------
int initiateHostStateTransition(ipmi::Context::ptr& ctx,
                                State::Host::Transition transition)
{
    // OpenBMC Host State Manager dbus framework
    constexpr auto hostStatePath = "/xyz/openbmc_project/state/host0";
    constexpr auto hostStateIntf = "xyz.openbmc_project.State.Host";

    // Convert to string equivalent of the passed in transition enum.
    auto request = State::convertForMessage(transition);

    std::string service;
    boost::system::error_code ec =
        ipmi::getService(ctx, hostStateIntf, hostStatePath, service);

    if (!ec)
    {
        ec = ipmi::setDbusProperty(ctx, service, hostStatePath, hostStateIntf,
                                   "RequestedHostTransition", request);
    }
    if (ec)
    {
        log<level::ERR>("Failed to initiate transition",
                        entry("EXCEPTION=%s, REQUEST=%s", ec.message().c_str(),
                              request.c_str()));
        return -1;
    }
    log<level::INFO>(
        "Transition request initiated successfully",
        entry("USERID=%d, REQUEST=%s", ctx->userId, request.c_str()));
    return 0;
}

//------------------------------------------
// Calls into Chassis State Manager Dbus object
//------------------------------------------
int initiateChassisStateTransition(ipmi::Context::ptr& ctx,
                                   State::Chassis::Transition transition)
{
    // OpenBMC Chassis State Manager dbus framework
    constexpr auto chassisStatePath = "/xyz/openbmc_project/state/chassis0";
    constexpr auto chassisStateIntf = "xyz.openbmc_project.State.Chassis";

    std::string service;
    boost::system::error_code ec =
        ipmi::getService(ctx, chassisStateIntf, chassisStatePath, service);

    // Convert to string equivalent of the passed in transition enum.
    auto request = State::convertForMessage(transition);

    if (!ec)
    {
        ec = ipmi::setDbusProperty(ctx, service, chassisStatePath,
                                   chassisStateIntf, "RequestedPowerTransition",
                                   request);
    }
    if (ec)
    {
        log<level::ERR>("Failed to initiate transition",
                        entry("EXCEPTION=%s, REQUEST=%s", ec.message().c_str(),
                              request.c_str()));
        return -1;
    }

    return 0;
}

//------------------------------------------
// Set Enabled property to inform NMI source
// handling to trigger a NMI_OUT BSOD.
//------------------------------------------
int setNmiProperty(ipmi::Context::ptr& ctx, const bool value)
{
    constexpr const char* nmiSourceObjPath =
        "/xyz/openbmc_project/Chassis/Control/NMISource";
    constexpr const char* nmiSourceIntf =
        "xyz.openbmc_project.Chassis.Control.NMISource";
    std::string bmcSourceSignal = "xyz.openbmc_project.Chassis.Control."
                                  "NMISource.BMCSourceSignal.ChassisCmd";

    std::string service;
    boost::system::error_code ec =
        ipmi::getService(ctx, nmiSourceIntf, nmiSourceObjPath, service);
    if (!ec)
    {
        ec = ipmi::setDbusProperty(ctx, service, nmiSourceObjPath,
                                   nmiSourceIntf, "BMCSource", bmcSourceSignal);
    }
    if (!ec)
    {
        ec = ipmi::setDbusProperty(ctx, service, nmiSourceObjPath,
                                   nmiSourceIntf, "Enabled", value);
    }
    if (ec)
    {
        log<level::ERR>("Failed to trigger NMI_OUT",
                        entry("EXCEPTION=%s", ec.message().c_str()));
        return -1;
    }

    return 0;
}

namespace power_policy
{

using namespace sdbusplus::xyz::openbmc_project::Control::Power::server;
using IpmiValue = uint8_t;
using DbusValue = RestorePolicy::Policy;

const std::map<DbusValue, IpmiValue> dbusToIpmi = {
    {RestorePolicy::Policy::AlwaysOff, 0x00},
    {RestorePolicy::Policy::Restore, 0x01},
    {RestorePolicy::Policy::AlwaysOn, 0x02}};

static constexpr uint8_t noChange = 0x03;
static constexpr uint8_t allSupport = 0x01 | 0x02 | 0x04;

/* helper function for Get Chassis Status Command
 */
std::optional<uint2_t> getPowerRestorePolicy()
{
    uint2_t restorePolicy = 0;
    using namespace chassis::internal;

    settings::Objects& objects = cache::getObjects();

    try
    {
        const auto& powerRestoreSetting =
            objects.map.at(powerRestoreIntf).front();
        ipmi::Value result = ipmi::getDbusProperty(
            *getSdBus(),
            objects.service(powerRestoreSetting, powerRestoreIntf).c_str(),
            powerRestoreSetting.c_str(), powerRestoreIntf,
            "PowerRestorePolicy");
        auto powerRestore = RestorePolicy::convertPolicyFromString(
            std::get<std::string>(result));
        restorePolicy = dbusToIpmi.at(powerRestore);
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(
            "Failed to fetch pgood property", entry("ERROR=%s", e.what()),
            entry("PATH=%s", objects.map.at(powerRestoreIntf).front().c_str()),
            entry("INTERFACE=%s", powerRestoreIntf));
        cache::objectsPtr.reset();
        return std::nullopt;
    }
    return std::make_optional(restorePolicy);
}

/*
 * getPowerStatus
 * helper function for Get Chassis Status Command
 * return - optional value for pgood (no value on error)
 */
std::optional<bool> getPowerStatus()
{
    bool powerGood = false;
    std::shared_ptr<sdbusplus::asio::connection> busp = getSdBus();
    try
    {
        constexpr const char* chassisStatePath =
            "/xyz/openbmc_project/state/chassis0";
        constexpr const char* chassisStateIntf =
            "xyz.openbmc_project.State.Chassis";
        auto service =
            ipmi::getService(*busp, chassisStateIntf, chassisStatePath);

        ipmi::Value powerState =
            ipmi::getDbusProperty(*busp, service, chassisStatePath,
                                  chassisStateIntf, "CurrentPowerState");
        powerGood = std::get<std::string>(powerState) ==
                    "xyz.openbmc_project.State.Chassis.PowerState.On";
    }
    catch (const std::exception& e)
    {
        try
        {
            // FIXME: some legacy modules use the older path; try that next
            constexpr const char* legacyPwrCtrlObj =
                "/org/openbmc/control/power0";
            constexpr const char* legacyPwrCtrlIntf =
                "org.openbmc.control.Power";
            auto service =
                ipmi::getService(*busp, legacyPwrCtrlIntf, legacyPwrCtrlObj);

            ipmi::Value variant = ipmi::getDbusProperty(
                *busp, service, legacyPwrCtrlObj, legacyPwrCtrlIntf, "pgood");
            powerGood = static_cast<bool>(std::get<int>(variant));
        }
        catch (const std::exception& e)
        {
            log<level::ERR>("Failed to fetch pgood property",
                            entry("ERROR=%s", e.what()));
            return std::nullopt;
        }
    }
    return std::make_optional(powerGood);
}

/*
 * getACFailStatus
 * helper function for Get Chassis Status Command
 * return - bool value for ACFail (false on error)
 */
bool getACFailStatus()
{
    constexpr const char* powerControlObj =
        "/xyz/openbmc_project/Chassis/Control/Power0";
    constexpr const char* powerControlIntf =
        "xyz.openbmc_project.Chassis.Control.Power";
    bool acFail = false;
    std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();
    try
    {
        auto service =
            ipmi::getService(*bus, powerControlIntf, powerControlObj);

        ipmi::Value variant = ipmi::getDbusProperty(
            *bus, service, powerControlObj, powerControlIntf, "PFail");
        acFail = std::get<bool>(variant);
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("Failed to fetch PFail property",
                        entry("ERROR=%s", e.what()),
                        entry("PATH=%s", powerControlObj),
                        entry("INTERFACE=%s", powerControlIntf));
    }
    return acFail;
}
} // namespace power_policy

static std::optional<bool> getButtonEnabled(const std::string& buttonPath,
                                            const std::string& buttonIntf)
{
    std::shared_ptr<sdbusplus::asio::connection> busp = getSdBus();
    bool buttonDisabled = false;
    try
    {
        auto service = ipmi::getService(*busp, buttonIntf, buttonPath);
        ipmi::Value enabled = ipmi::getDbusProperty(*busp, service, buttonPath,
                                                    buttonIntf, "Enabled");
        buttonDisabled = !std::get<bool>(enabled);
    }
    catch (const sdbusplus::exception_t& e)
    {
        log<level::ERR>("Fail to get button Enabled property",
                        entry("PATH=%s", buttonPath.c_str()),
                        entry("ERROR=%s", e.what()));
        return std::nullopt;
    }
    return std::make_optional(buttonDisabled);
}

static bool setButtonEnabled(ipmi::Context::ptr& ctx,
                             const std::string& buttonPath,
                             const std::string& buttonIntf, bool enable)
{
    std::string service;
    boost::system::error_code ec;
    ec = ipmi::getService(ctx, buttonIntf, buttonPath, service);
    if (!ec)
    {
        ec = ipmi::setDbusProperty(ctx, service, buttonPath, buttonIntf,
                                   "Enabled", enable);
    }
    if (ec)
    {
        log<level::ERR>("Fail to set button Enabled property",
                        entry("SERVICE=%s", service.c_str()),
                        entry("PATH=%s", buttonPath.c_str()),
                        entry("ERROR=%s", ec.message().c_str()));
        return false;
    }
    return true;
}

static std::optional<bool> getChassisIntrusionStatus(ipmi::Context::ptr& ctx)
{
    constexpr const char* chassisIntrusionPath =
        "/xyz/openbmc_project/Chassis/Intrusion";
    constexpr const char* chassisIntrusionInf =
        "xyz.openbmc_project.Chassis.Intrusion";

    std::string service;
    boost::system::error_code ec = ipmi::getService(
        ctx, chassisIntrusionInf, chassisIntrusionPath, service);
    if (!ec)
    {
        std::string chassisIntrusionStr;
        ec = ipmi::getDbusProperty<std::string>(
            ctx, service, chassisIntrusionPath, chassisIntrusionInf, "Status",
            chassisIntrusionStr);
        if (!ec)
        {
            bool ret =
                (chassisIntrusionStr == "HardwareIntrusion") ? true : false;
            return std::make_optional(ret);
        }
    }
    log<level::ERR>("Fail to get Chassis Intrusion Status property",
                    entry("PATH=%s", chassisIntrusionPath),
                    entry("INTERFACE=%s", chassisIntrusionInf),
                    entry("ERROR=%s", ec.message().c_str()));
    return std::nullopt;
}

//----------------------------------------------------------------------
// Get Chassis Status commands
//----------------------------------------------------------------------
ipmi::RspType<bool,    // Power is on
              bool,    // Power overload
              bool,    // Interlock
              bool,    // power fault
              bool,    // power control fault
              uint2_t, // power restore policy
              bool,    // reserved

              bool, // AC failed
              bool, // last power down caused by a Power overload
              bool, // last power down caused by a power interlock
              bool, // last power down caused by power fault
              bool, // last ‘Power is on’ state was entered via IPMI command
              uint3_t, // reserved

              bool,    // Chassis intrusion active
              bool,    // Front Panel Lockout active
              bool,    // Drive Fault
              bool,    // Cooling/fan fault detected
              uint2_t, // Chassis Identify State
              bool,    // Chassis Identify command and state info supported
              bool,    // reserved

              bool, // Power off button disabled
              bool, // Reset button disabled
              bool, // Diagnostic Interrupt button disabled
              bool, // Standby (sleep) button disabled
              bool, // Power off button disable allowed
              bool, // Reset button disable allowed
              bool, // Diagnostic Interrupt button disable allowed
              bool  // Standby (sleep) button disable allowed
              >
    ipmiGetChassisStatus(ipmi::Context::ptr& ctx)
{
    using namespace chassis::internal;
    std::optional<uint2_t> restorePolicy =
        power_policy::getPowerRestorePolicy();
    std::optional<bool> powerGood = power_policy::getPowerStatus();
    if (!restorePolicy || !powerGood)
    {
        return ipmi::responseUnspecifiedError();
    }

    //  Front Panel Button Capabilities and disable/enable status(Optional)
    std::optional<bool> powerButtonReading =
        getButtonEnabled(powerButtonPath, powerButtonIntf);
    // allow disable if the interface is present
    bool powerButtonDisableAllow = static_cast<bool>(powerButtonReading);
    // default return the button is enabled (not disabled)
    bool powerButtonDisabled = false;
    if (powerButtonDisableAllow)
    {
        // return the real value of the button status, if present
        powerButtonDisabled = *powerButtonReading;
    }

    std::optional<bool> resetButtonReading =
        getButtonEnabled(resetButtonPath, resetButtonIntf);
    // allow disable if the interface is present
    bool resetButtonDisableAllow = static_cast<bool>(resetButtonReading);
    // default return the button is enabled (not disabled)
    bool resetButtonDisabled = false;
    if (resetButtonDisableAllow)
    {
        // return the real value of the button status, if present
        resetButtonDisabled = *resetButtonReading;
    }

    bool powerDownAcFailed = power_policy::getACFailStatus();

    bool chassisIntrusionActive = false;
    std::optional<bool> chassisIntrusionStatus = getChassisIntrusionStatus(ctx);
    if (chassisIntrusionStatus)
    {
        chassisIntrusionActive = chassisIntrusionStatus.value();
    }

    // This response has a lot of hard-coded, unsupported fields
    // They are set to false or 0
    constexpr bool powerOverload = false;
    constexpr bool chassisInterlock = false;
    constexpr bool powerFault = false;
    constexpr bool powerControlFault = false;
    constexpr bool powerDownOverload = false;
    constexpr bool powerDownInterlock = false;
    constexpr bool powerDownPowerFault = false;
    constexpr bool powerStatusIPMI = false;
    constexpr bool frontPanelLockoutActive = false;
    constexpr bool driveFault = false;
    constexpr bool coolingFanFault = false;
    // chassisIdentifySupport set because this command is implemented
    constexpr bool chassisIdentifySupport = true;
    uint2_t chassisIdentifyState = types::enum_cast<uint2_t>(chassisIDState);
    constexpr bool diagButtonDisabled = false;
    constexpr bool sleepButtonDisabled = false;
    constexpr bool diagButtonDisableAllow = false;
    constexpr bool sleepButtonDisableAllow = false;

    return ipmi::responseSuccess(
        *powerGood, powerOverload, chassisInterlock, powerFault,
        powerControlFault, *restorePolicy,
        false, // reserved

        powerDownAcFailed, powerDownOverload, powerDownInterlock,
        powerDownPowerFault, powerStatusIPMI,
        uint3_t(0), // reserved

        chassisIntrusionActive, frontPanelLockoutActive, driveFault,
        coolingFanFault, chassisIdentifyState, chassisIdentifySupport,
        false, // reserved

        powerButtonDisabled, resetButtonDisabled, diagButtonDisabled,
        sleepButtonDisabled, powerButtonDisableAllow, resetButtonDisableAllow,
        diagButtonDisableAllow, sleepButtonDisableAllow);
}

enum class IpmiRestartCause
{
    Unknown = 0x0,
    RemoteCommand = 0x1,
    ResetButton = 0x2,
    PowerButton = 0x3,
    WatchdogTimer = 0x4,
    PowerPolicyAlwaysOn = 0x6,
    PowerPolicyPreviousState = 0x7,
    SoftReset = 0xa,
};

static IpmiRestartCause
    restartCauseToIpmiRestartCause(State::Host::RestartCause cause)
{
    switch (cause)
    {
        case State::Host::RestartCause::Unknown:
        {
            return IpmiRestartCause::Unknown;
        }
        case State::Host::RestartCause::RemoteCommand:
        {
            return IpmiRestartCause::RemoteCommand;
        }
        case State::Host::RestartCause::ResetButton:
        {
            return IpmiRestartCause::ResetButton;
        }
        case State::Host::RestartCause::PowerButton:
        {
            return IpmiRestartCause::PowerButton;
        }
        case State::Host::RestartCause::WatchdogTimer:
        {
            return IpmiRestartCause::WatchdogTimer;
        }
        case State::Host::RestartCause::PowerPolicyAlwaysOn:
        {
            return IpmiRestartCause::PowerPolicyAlwaysOn;
        }
        case State::Host::RestartCause::PowerPolicyPreviousState:
        {
            return IpmiRestartCause::PowerPolicyPreviousState;
        }
        case State::Host::RestartCause::SoftReset:
        {
            return IpmiRestartCause::SoftReset;
        }
        default:
        {
            return IpmiRestartCause::Unknown;
        }
    }
}

/*
 * getRestartCause
 * helper function for Get Host restart cause Command
 * return - optional value for RestartCause (no value on error)
 */
static std::optional<uint4_t> getRestartCause(ipmi::Context::ptr ctx)
{
    constexpr const char* restartCausePath =
        "/xyz/openbmc_project/control/host0/restart_cause";
    constexpr const char* restartCauseIntf =
        "xyz.openbmc_project.Control.Host.RestartCause";

    std::string service;
    boost::system::error_code ec =
        ipmi::getService(ctx, restartCauseIntf, restartCausePath, service);
    if (!ec)
    {
        std::string restartCauseStr;
        ec = ipmi::getDbusProperty<std::string>(
            ctx, service, restartCausePath, restartCauseIntf, "RestartCause",
            restartCauseStr);
        if (!ec)
        {
            auto cause =
                State::Host::convertRestartCauseFromString(restartCauseStr);
            return types::enum_cast<uint4_t>(
                restartCauseToIpmiRestartCause(cause));
        }
    }

    log<level::ERR>("Failed to fetch RestartCause property",
                    entry("ERROR=%s", ec.message().c_str()),
                    entry("PATH=%s", restartCausePath),
                    entry("INTERFACE=%s", restartCauseIntf));
    return std::nullopt;
}

ipmi::RspType<uint4_t, // Restart Cause
              uint4_t, // reserved
              uint8_t  // channel number (not supported)
              >
    ipmiGetSystemRestartCause(ipmi::Context::ptr ctx)
{
    std::optional<uint4_t> cause = getRestartCause(ctx);
    if (!cause)
    {
        return ipmi::responseUnspecifiedError();
    }

    constexpr uint4_t reserved = 0;
    auto channel = static_cast<uint8_t>(ctx->channel);
    return ipmi::responseSuccess(cause.value(), reserved, channel);
}
/** @brief Implementation of chassis control command
 *
 *  @param - chassisControl command byte
 *
 *  @return  Success or InvalidFieldRequest.
 */
ipmi::RspType<> ipmiChassisControl(ipmi::Context::ptr& ctx,
                                   uint8_t chassisControl)
{
    int rc = 0;
    switch (chassisControl)
    {
        case CMD_POWER_ON:
            rc = initiateHostStateTransition(ctx, State::Host::Transition::On);
            break;
        case CMD_POWER_OFF:
            rc = initiateChassisStateTransition(
                ctx, State::Chassis::Transition::Off);
            break;
        case CMD_HARD_RESET:
            rc = initiateHostStateTransition(
                ctx, State::Host::Transition::ForceWarmReboot);
            break;
        case CMD_POWER_CYCLE:
            rc = initiateHostStateTransition(ctx,
                                             State::Host::Transition::Reboot);
            break;
        case CMD_SOFT_OFF_VIA_OVER_TEMP:
            rc = initiateHostStateTransition(ctx, State::Host::Transition::Off);
            break;
        case CMD_PULSE_DIAGNOSTIC_INTR:
            rc = setNmiProperty(ctx, true);
            break;

        default:
        {
            log<level::ERR>("Invalid Chassis Control command",
                            entry("CMD=0x%X", chassisControl));
            return ipmi::responseInvalidFieldRequest();
        }
    }

    return ((rc < 0) ? ipmi::responseUnspecifiedError()
                     : ipmi::responseSuccess());
}

/** @brief Return D-Bus connection string to enclosure identify LED object
 *
 *  @param[in, out] connection - connection to D-Bus object
 *  @return a IPMI return code
 */
std::string getEnclosureIdentifyConnection()
{
    // lookup enclosure_identify group owner(s) in mapper
    auto mapperCall = chassis::internal::dbus.new_method_call(
        ipmi::MAPPER_BUS_NAME, ipmi::MAPPER_OBJ, ipmi::MAPPER_INTF,
        "GetObject");

    mapperCall.append(identify_led_object_name);
    static const std::vector<std::string> interfaces = {
        "xyz.openbmc_project.Led.Group"};
    mapperCall.append(interfaces);
    auto mapperReply = chassis::internal::dbus.call(mapperCall);
    if (mapperReply.is_method_error())
    {
        log<level::ERR>("Chassis Identify: Error communicating to mapper.");
        elog<InternalFailure>();
    }
    std::vector<std::pair<std::string, std::vector<std::string>>> mapperResp;
    mapperReply.read(mapperResp);

    if (mapperResp.size() != encIdentifyObjectsSize)
    {
        log<level::ERR>(
            "Invalid number of enclosure identify objects.",
            entry("ENC_IDENTITY_OBJECTS_SIZE=%d", mapperResp.size()));
        elog<InternalFailure>();
    }
    auto pair = mapperResp[encIdentifyObjectsSize - 1];
    return pair.first;
}

/** @brief Turn On/Off enclosure identify LED
 *
 *  @param[in] flag - true to turn on LED, false to turn off
 *  @return a IPMI return code
 */
void enclosureIdentifyLed(bool flag)
{
    using namespace chassis::internal;
    std::string connection = std::move(getEnclosureIdentifyConnection());
    auto msg = std::string("enclosureIdentifyLed(") +
               boost::lexical_cast<std::string>(flag) + ")";
    log<level::DEBUG>(msg.c_str());
    auto led =
        dbus.new_method_call(connection.c_str(), identify_led_object_name,
                             "org.freedesktop.DBus.Properties", "Set");
    led.append("xyz.openbmc_project.Led.Group", "Asserted",
               std::variant<bool>(flag));
    auto ledReply = dbus.call(led);
    if (ledReply.is_method_error())
    {
        log<level::ERR>("Chassis Identify: Error Setting State On/Off\n",
                        entry("LED_STATE=%d", flag));
        elog<InternalFailure>();
    }
}

/** @brief Callback method to turn off LED
 */
void enclosureIdentifyLedOff()
{
    try
    {
        chassisIDState = ChassisIDState::off;
        enclosureIdentifyLed(false);
    }
    catch (const InternalFailure& e)
    {
        report<InternalFailure>();
    }
}

/** @brief Create timer to turn on and off the enclosure LED
 */
void createIdentifyTimer()
{
    if (!identifyTimer)
    {
        identifyTimer =
            std::make_unique<phosphor::Timer>(enclosureIdentifyLedOff);
    }
}

ipmi::RspType<> ipmiChassisIdentify(std::optional<uint8_t> interval,
                                    std::optional<uint8_t> force)
{
    uint8_t identifyInterval = interval.value_or(DEFAULT_IDENTIFY_TIME_OUT);
    bool forceIdentify = force.value_or(0) & 0x01;

    if (identifyInterval || forceIdentify)
    {
        // stop the timer if already started;
        // for force identify we should not turn off LED
        identifyTimer->stop();
        try
        {
            chassisIDState = ChassisIDState::temporaryOn;
            enclosureIdentifyLed(true);
        }
        catch (const InternalFailure& e)
        {
            report<InternalFailure>();
            return ipmi::responseResponseError();
        }

        if (forceIdentify)
        {
            chassisIDState = ChassisIDState::indefiniteOn;
            return ipmi::responseSuccess();
        }
        // start the timer
        auto time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::seconds(identifyInterval));
        identifyTimer->start(time);
    }
    else if (!identifyInterval)
    {
        identifyTimer->stop();
        enclosureIdentifyLedOff();
    }
    return ipmi::responseSuccess();
}

namespace boot_options
{

using namespace sdbusplus::xyz::openbmc_project::Control::Boot::server;
using IpmiValue = uint8_t;
constexpr auto ipmiDefault = 0;

std::map<IpmiValue, Type::Types> typeIpmiToDbus = {{0x00, Type::Types::Legacy},
                                                   {0x01, Type::Types::EFI}};

std::map<IpmiValue, Source::Sources> sourceIpmiToDbus = {
    {0x01, Source::Sources::Network},
    {0x02, Source::Sources::Disk},
    {0x05, Source::Sources::ExternalMedia},
    {0x0f, Source::Sources::RemovableMedia},
    {ipmiDefault, Source::Sources::Default}};

std::map<IpmiValue, Mode::Modes> modeIpmiToDbus = {
#ifdef ENABLE_BOOT_FLAG_SAFE_MODE_SUPPORT
    {0x03, Mode::Modes::Safe},
#endif // ENABLE_BOOT_SAFE_MODE_SUPPORT
    {0x06, Mode::Modes::Setup},
    {ipmiDefault, Mode::Modes::Regular}};

std::map<Type::Types, IpmiValue> typeDbusToIpmi = {{Type::Types::Legacy, 0x00},
                                                   {Type::Types::EFI, 0x01}};

std::map<Source::Sources, IpmiValue> sourceDbusToIpmi = {
    {Source::Sources::Network, 0x01},
    {Source::Sources::Disk, 0x02},
    {Source::Sources::ExternalMedia, 0x05},
    {Source::Sources::RemovableMedia, 0x0f},
    {Source::Sources::Default, ipmiDefault}};

std::map<Mode::Modes, IpmiValue> modeDbusToIpmi = {
#ifdef ENABLE_BOOT_FLAG_SAFE_MODE_SUPPORT
    {Mode::Modes::Safe, 0x03},
#endif // ENABLE_BOOT_SAFE_MODE_SUPPORT
    {Mode::Modes::Setup, 0x06},
    {Mode::Modes::Regular, ipmiDefault}};

} // namespace boot_options

/** @brief Get the property value for boot source
 *  @param[in] ctx - context pointer
 *  @param[out] source - boot source value
 *  @return On failure return IPMI error.
 */
static ipmi::Cc getBootSource(ipmi::Context::ptr& ctx, Source::Sources& source)
{
    using namespace chassis::internal;
    std::string result;
    std::string service;
    boost::system::error_code ec =
        getService(ctx, bootSourceIntf, bootSettingsPath, service);
    if (!ec)
    {
        ec = ipmi::getDbusProperty(ctx, service, bootSettingsPath,
                                   bootSourceIntf, "BootSource", result);
        if (!ec)
        {
            source = Source::convertSourcesFromString(result);
            return ipmi::ccSuccess;
        }
    }
    log<level::ERR>("Error in BootSource Get",
                    entry("ERROR=%s", ec.message().c_str()));
    return ipmi::ccUnspecifiedError;
}

/** @brief Set the property value for boot source
 *  @param[in] ctx - context pointer
 *  @param[in] source - boot source value
 *  @return On failure return IPMI error.
 */
static ipmi::Cc setBootSource(ipmi::Context::ptr& ctx,
                              const Source::Sources& source)
{
    using namespace chassis::internal;
    std::string service;
    boost::system::error_code ec =
        getService(ctx, bootSourceIntf, bootSettingsPath, service);
    if (!ec)
    {
        ec = ipmi::setDbusProperty(ctx, service, bootSettingsPath,
                                   bootSourceIntf, "BootSource",
                                   convertForMessage(source));
        if (!ec)
        {
            return ipmi::ccSuccess;
        }
    }
    log<level::ERR>("Error in BootSource Set",
                    entry("ERROR=%s", ec.message().c_str()));
    return ipmi::ccUnspecifiedError;
}

/** @brief Get the property value for boot mode
 *  @param[in] ctx - context pointer
 *  @param[out] mode - boot mode value
 *  @return On failure return IPMI error.
 */
static ipmi::Cc getBootMode(ipmi::Context::ptr& ctx, Mode::Modes& mode)
{
    using namespace chassis::internal;
    std::string result;
    std::string service;
    boost::system::error_code ec =
        getService(ctx, bootModeIntf, bootSettingsPath, service);
    if (!ec)
    {
        ec = ipmi::getDbusProperty(ctx, service, bootSettingsPath, bootModeIntf,
                                   "BootMode", result);
        if (!ec)
        {
            mode = Mode::convertModesFromString(result);
            return ipmi::ccSuccess;
        }
    }
    log<level::ERR>("Error in BootMode Get",
                    entry("ERROR=%s", ec.message().c_str()));
    return ipmi::ccUnspecifiedError;
}

/** @brief Set the property value for boot mode
 *  @param[in] ctx - context pointer
 *  @param[in] mode - boot mode value
 *  @return On failure return IPMI error.
 */
static ipmi::Cc setBootMode(ipmi::Context::ptr& ctx, const Mode::Modes& mode)
{
    using namespace chassis::internal;
    std::string service;
    boost::system::error_code ec =
        getService(ctx, bootModeIntf, bootSettingsPath, service);
    if (!ec)
    {
        ec = ipmi::setDbusProperty(ctx, service, bootSettingsPath, bootModeIntf,
                                   "BootMode", convertForMessage(mode));
        if (!ec)
        {
            return ipmi::ccSuccess;
        }
    }
    log<level::ERR>("Error in BootMode Set",
                    entry("ERROR=%s", ec.message().c_str()));
    return ipmi::ccUnspecifiedError;
}

/** @brief Get the property value for boot type
 *  @param[in] ctx - context pointer
 *  @param[out] type - boot type value
 *  @return On failure return IPMI error.
 */
static ipmi::Cc getBootType(ipmi::Context::ptr& ctx, Type::Types& type)
{
    using namespace chassis::internal;
    std::string result;
    std::string service;
    boost::system::error_code ec =
        getService(ctx, bootTypeIntf, bootSettingsPath, service);

    // Don't throw error if BootType interface is not present.
    // This interface is not relevant for some Host architectures
    // (for example POWER). In this case we don't won't IPMI to
    // return an error, but simply return bootType as EFI.
    type = Type::Types::EFI;
    if (!ec)
    {
        ec = ipmi::getDbusProperty(ctx, service, bootSettingsPath, bootTypeIntf,
                                   "BootType", result);
        if (ec)
        {
            log<level::ERR>("Error in BootType Get",
                            entry("ERROR=%s", ec.message().c_str()));
            return ipmi::ccUnspecifiedError;
        }
        type = Type::convertTypesFromString(result);
    }

    return ipmi::ccSuccess;
}

/** @brief Set the property value for boot type
 *  @param[in] ctx - context pointer
 *  @param[in] type - boot type value
 *  @return On failure return IPMI error.
 */
static ipmi::Cc setBootType(ipmi::Context::ptr& ctx, const Type::Types& type)
{
    using namespace chassis::internal;
    std::string service;
    boost::system::error_code ec =
        getService(ctx, bootTypeIntf, bootSettingsPath, service);
    if (!ec)
    {
        ec = ipmi::setDbusProperty(ctx, service, bootSettingsPath, bootTypeIntf,
                                   "BootType", convertForMessage(type));
        if (ec)
        {
            log<level::ERR>("Error in BootType Set",
                            entry("ERROR=%s", ec.message().c_str()));
            return ipmi::ccUnspecifiedError;
        }
    }
    // Don't throw error if BootType interface is not present.
    // This interface is not relevant for some Host architectures
    // (for example POWER). In this case we don't won't IPMI to
    // return an error, but want to just skip this function.
    return ipmi::ccSuccess;
}

/** @brief Get the property value for boot override enable
 *  @param[in] ctx - context pointer
 *  @param[out] enable - boot override enable
 *  @return On failure return IPMI error.
 */
static ipmi::Cc getBootEnable(ipmi::Context::ptr& ctx, bool& enable)
{
    using namespace chassis::internal;
    std::string result;
    std::string service;
    boost::system::error_code ec =
        getService(ctx, bootEnableIntf, bootSettingsPath, service);
    if (!ec)
    {
        ec = ipmi::getDbusProperty(ctx, service, bootSettingsPath,
                                   bootEnableIntf, "Enabled", enable);
        if (!ec)
        {
            return ipmi::ccSuccess;
        }
    }
    log<level::ERR>("Error in Boot Override Enable Get",
                    entry("ERROR=%s", ec.message().c_str()));
    return ipmi::ccUnspecifiedError;
}

/** @brief Set the property value for boot override enable
 *  @param[in] ctx - context pointer
 *  @param[in] enable - boot override enable
 *  @return On failure return IPMI error.
 */
static ipmi::Cc setBootEnable(ipmi::Context::ptr& ctx, const bool& enable)
{
    using namespace chassis::internal;
    std::string service;
    boost::system::error_code ec =
        getService(ctx, bootEnableIntf, bootSettingsPath, service);
    if (!ec)
    {
        ec = ipmi::setDbusProperty(ctx, service, bootSettingsPath,
                                   bootEnableIntf, "Enabled", enable);
        if (!ec)
        {
            return ipmi::ccSuccess;
        }
    }
    log<level::ERR>("Error in Boot Source Override Enable Set",
                    entry("ERROR=%s", ec.message().c_str()));
    return ipmi::ccUnspecifiedError;
}

/** @brief Get the property value for boot override one-time
 *  @param[in] ctx - context pointer
 *  @param[out] onetime - boot override one-time
 *  @return On failure return IPMI error.
 */
static ipmi::Cc getBootOneTime(ipmi::Context::ptr& ctx, bool& onetime)
{
    using namespace chassis::internal;
    std::string result;
    std::string service;
    boost::system::error_code ec =
        getService(ctx, bootOneTimeIntf, bootSettingsOneTimePath, service);
    if (!ec)
    {
        ec = ipmi::getDbusProperty(ctx, service, bootSettingsOneTimePath,
                                   bootOneTimeIntf, "Enabled", onetime);
        if (!ec)
        {
            return ipmi::ccSuccess;
        }
    }
    log<level::ERR>("Error in Boot Override OneTime Get",
                    entry("ERROR=%s", ec.message().c_str()));
    return ipmi::ccUnspecifiedError;
}

/** @brief Set the property value for boot override one-time
 *  @param[in] ctx - context pointer
 *  @param[in] onetime - boot override one-time
 *  @return On failure return IPMI error.
 */
static ipmi::Cc setBootOneTime(ipmi::Context::ptr& ctx, const bool& onetime)
{
    using namespace chassis::internal;
    std::string service;
    boost::system::error_code ec =
        getService(ctx, bootOneTimeIntf, bootSettingsOneTimePath, service);
    if (!ec)
    {
        ec = ipmi::setDbusProperty(ctx, service, bootSettingsOneTimePath,
                                   bootOneTimeIntf, "Enabled", onetime);
        if (!ec)
        {
            return ipmi::ccSuccess;
        }
    }
    log<level::ERR>("Error in Boot Source Override OneTime Set",
                    entry("ERROR=%s", ec.message().c_str()));
    return ipmi::ccUnspecifiedError;
}

static constexpr uint8_t setComplete = 0x0;
static constexpr uint8_t setInProgress = 0x1;
static uint8_t transferStatus = setComplete;
static uint8_t bootFlagValidBitClr = 0;
static uint5_t bootInitiatorAckData = 0x0;
static bool cmosClear = false;

/** @brief implements the Get Chassis system boot option
 *  @param ctx - context pointer
 *  @param bootOptionParameter   - boot option parameter selector
 *  @param reserved1    - reserved bit
 *  @param setSelector  - selects a particular block or set of parameters
 *                        under the given parameter selector
 *                        write as 00h if parameter doesn't use a setSelector
 *  @param blockSelector- selects a particular block within a set of
 *                        parameters write as 00h if parameter doesn't use a
 *                        blockSelector
 *
 *  @return IPMI completion code plus response data
 *  @return Payload contains below parameters:
 *   version             - parameter version
 *   bootOptionParameter - boot option parameter selector
 *   parmIndicator - parameter valid/invalid indicator
 *   data          - configuration parameter data
 */
ipmi::RspType<ipmi::message::Payload>
    ipmiChassisGetSysBootOptions(ipmi::Context::ptr ctx,
                                 uint7_t bootOptionParameter, bool reserved1,
                                 [[maybe_unused]] uint8_t setSelector,
                                 [[maybe_unused]] uint8_t blockSelector)
{
    ipmi::Cc rc;
    if (reserved1)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    constexpr uint4_t version = 0x01;
    ipmi::message::Payload response;
    response.pack(version, uint4_t{});
    using namespace boot_options;

    IpmiValue bootOption = ipmiDefault;

    if (types::enum_cast<BootOptionParameter>(bootOptionParameter) ==
        BootOptionParameter::setInProgress)
    {
        response.pack(bootOptionParameter, reserved1, transferStatus);
        return ipmi::responseSuccess(std::move(response));
    }

    if (types::enum_cast<BootOptionParameter>(bootOptionParameter) ==
        BootOptionParameter::bootInfo)
    {
        constexpr uint8_t writeMask = 0;
        response.pack(bootOptionParameter, reserved1, writeMask,
                      bootInitiatorAckData);
        return ipmi::responseSuccess(std::move(response));
    }

    if (types::enum_cast<BootOptionParameter>(bootOptionParameter) ==
        BootOptionParameter::bootFlagValidClr)
    {
        response.pack(bootOptionParameter, reserved1,
                      uint5_t{bootFlagValidBitClr}, uint3_t{});
        return ipmi::responseSuccess(std::move(response));
    }

    /*
     * Parameter #5 means boot flags. Please refer to 28.13 of ipmi doc.
     * This is the only parameter used by petitboot.
     */
    if (types::enum_cast<BootOptionParameter>(bootOptionParameter) ==
        BootOptionParameter::bootFlags)
    {
        using namespace chassis::internal;
        using namespace chassis::internal::cache;

        try
        {
            Source::Sources bootSource;
            rc = getBootSource(ctx, bootSource);
            if (rc != ipmi::ccSuccess)
            {
                return ipmi::response(rc);
            }

            Type::Types bootType;
            rc = getBootType(ctx, bootType);
            if (rc != ipmi::ccSuccess)
            {
                return ipmi::response(rc);
            }

            Mode::Modes bootMode;
            rc = getBootMode(ctx, bootMode);
            if (rc != ipmi::ccSuccess)
            {
                return ipmi::response(rc);
            }

            bootOption = sourceDbusToIpmi.at(bootSource);
            if ((Mode::Modes::Regular == bootMode) &&
                (Source::Sources::Default == bootSource))
            {
                bootOption = ipmiDefault;
            }
            else if (Source::Sources::Default == bootSource)
            {
                bootOption = modeDbusToIpmi.at(bootMode);
            }

            IpmiValue biosBootType = typeDbusToIpmi.at(bootType);

            bool oneTimeEnabled;
            rc = getBootOneTime(ctx, oneTimeEnabled);
            if (rc != ipmi::ccSuccess)
            {
                return ipmi::response(rc);
            }

            uint1_t permanent = oneTimeEnabled ? 0 : 1;

            bool valid;
            rc = getBootEnable(ctx, valid);
            if (rc != ipmi::ccSuccess)
            {
                return ipmi::response(rc);
            }

            uint1_t validFlag = valid ? 1 : 0;

            response.pack(bootOptionParameter, reserved1, uint5_t{},
                          uint1_t{biosBootType}, uint1_t{permanent},
                          uint1_t{validFlag}, uint2_t{}, uint4_t{bootOption},
                          uint1_t{}, cmosClear, uint8_t{}, uint8_t{},
                          uint8_t{});
            return ipmi::responseSuccess(std::move(response));
        }
        catch (const InternalFailure& e)
        {
            cache::objectsPtr.reset();
            report<InternalFailure>();
            return ipmi::responseUnspecifiedError();
        }
    }
    else
    {
        if ((bootOptionParameter >= oemParmStart) &&
            (bootOptionParameter <= oemParmEnd))
        {
            if (types::enum_cast<BootOptionParameter>(bootOptionParameter) ==
                BootOptionParameter::opalNetworkSettings)
            {
                response.pack(bootOptionParameter, reserved1);
                int ret = getHostNetworkData(response);
                if (ret < 0)
                {
                    response.trailingOk = true;
                    log<level::ERR>(
                        "getHostNetworkData failed for GetSysBootOptions.");
                    return ipmi::responseUnspecifiedError();
                }
                else
                {
                    return ipmi::responseSuccess(std::move(response));
                }
            }
            else
            {
                log<level::ERR>(
                    "ipmiChassisGetSysBootOptions: Unsupported parameter",
                    entry("PARAM=0x%x",
                          static_cast<uint8_t>(bootOptionParameter)));
                return ipmi::responseParmNotSupported();
            }
        }
        else
        {
            log<level::ERR>(
                "ipmiChassisGetSysBootOptions: Unsupported parameter",
                entry("PARAM=0x%x", static_cast<uint8_t>(bootOptionParameter)));
            return ipmi::responseParmNotSupported();
        }
    }
    return ipmi::responseUnspecifiedError();
}

ipmi::RspType<> ipmiChassisSetSysBootOptions(ipmi::Context::ptr ctx,
                                             uint7_t parameterSelector, bool,
                                             ipmi::message::Payload& data)
{
    using namespace boot_options;
    ipmi::Cc rc;

    if (types::enum_cast<BootOptionParameter>(parameterSelector) ==
        BootOptionParameter::setInProgress)
    {
        uint2_t setInProgressFlag;
        uint6_t rsvd;
        if (data.unpack(setInProgressFlag, rsvd) != 0 || !data.fullyUnpacked())
        {
            return ipmi::responseReqDataLenInvalid();
        }
        if (rsvd)
        {
            return ipmi::responseInvalidFieldRequest();
        }
        if ((transferStatus == setInProgress) &&
            (static_cast<uint8_t>(setInProgressFlag) != setComplete))
        {
            return ipmi::response(IPMI_CC_FAIL_SET_IN_PROGRESS);
        }
        transferStatus = static_cast<uint8_t>(setInProgressFlag);
        return ipmi::responseSuccess();
    }

    /*  000101
     * Parameter #5 means boot flags. Please refer to 28.13 of ipmi doc.
     * This is the only parameter used by petitboot.
     */

    if (types::enum_cast<BootOptionParameter>(parameterSelector) ==
        BootOptionParameter::bootFlags)
    {
        uint5_t rsvd;
        bool validFlag;
        bool permanent;
        bool biosBootType;
        bool lockOutResetButton;
        bool screenBlank;
        uint4_t bootDeviceSelector;
        bool lockKeyboard;
        uint8_t data3;
        uint4_t biosInfo;
        uint4_t rsvd1;
        uint5_t deviceInstance;
        uint3_t rsvd2;

        if (data.unpack(rsvd, biosBootType, permanent, validFlag,
                        lockOutResetButton, screenBlank, bootDeviceSelector,
                        lockKeyboard, cmosClear, data3, biosInfo, rsvd1,
                        deviceInstance, rsvd2) != 0 ||
            !data.fullyUnpacked())
        {
            return ipmi::responseReqDataLenInvalid();
        }
        if (rsvd || rsvd1 || rsvd2)
        {
            return ipmi::responseInvalidFieldRequest();
        }

        using namespace chassis::internal;
        using namespace chassis::internal::cache;

        try
        {
            rc = setBootOneTime(ctx, !permanent);
            if (rc != ipmi::ccSuccess)
            {
                return ipmi::response(rc);
            }

            rc = setBootEnable(ctx, validFlag);
            if (rc != ipmi::ccSuccess)
            {
                return ipmi::response(rc);
            }

            auto modeItr =
                modeIpmiToDbus.find(static_cast<uint8_t>(bootDeviceSelector));
            auto typeItr =
                typeIpmiToDbus.find(static_cast<uint8_t>(biosBootType));
            auto sourceItr =
                sourceIpmiToDbus.find(static_cast<uint8_t>(bootDeviceSelector));
            if (sourceIpmiToDbus.end() != sourceItr)
            {
                rc = setBootSource(ctx, sourceItr->second);
                if (rc != ipmi::ccSuccess)
                {
                    return ipmi::response(rc);
                }
                // If a set boot device is mapping to a boot source, then reset
                // the boot mode D-Bus property to default.
                // This way the ipmid code can determine which property is not
                // at the default value
                if (sourceItr->second != Source::Sources::Default)
                {
                    rc = setBootMode(ctx, Mode::Modes::Regular);
                    if (rc != ipmi::ccSuccess)
                    {
                        return ipmi::response(rc);
                    }
                }
            }

            if (typeIpmiToDbus.end() != typeItr)
            {
                rc = setBootType(ctx, typeItr->second);
                if (rc != ipmi::ccSuccess)
                {
                    return ipmi::response(rc);
                }
            }

            if (modeIpmiToDbus.end() != modeItr)
            {
                rc = setBootMode(ctx, modeItr->second);
                if (rc != ipmi::ccSuccess)
                {
                    return ipmi::response(rc);
                }
                // If a set boot device is mapping to a boot mode, then reset
                // the boot source D-Bus property to default.
                // This way the ipmid code can determine which property is not
                // at the default value
                if (modeItr->second != Mode::Modes::Regular)
                {
                    rc = setBootSource(ctx, Source::Sources::Default);
                    if (rc != ipmi::ccSuccess)
                    {
                        return ipmi::response(rc);
                    }
                }
            }
            if ((modeIpmiToDbus.end() == modeItr) &&
                (typeIpmiToDbus.end() == typeItr) &&
                (sourceIpmiToDbus.end() == sourceItr))
            {
                // return error if boot option is not supported
                log<level::ERR>(
                    "ipmiChassisSetSysBootOptions: Boot option not supported");
                return ipmi::responseInvalidFieldRequest();
            }
        }
        catch (const sdbusplus::exception_t& e)
        {
            objectsPtr.reset();
            report<InternalFailure>();
            log<level::ERR>(
                "ipmiChassisSetSysBootOptions: Error in setting Boot "
                "flag parameters");
            return ipmi::responseUnspecifiedError();
        }
    }
    else if (types::enum_cast<BootOptionParameter>(parameterSelector) ==
             BootOptionParameter::bootInfo)
    {
        uint8_t writeMak;
        uint5_t bootInfoAck;
        uint3_t rsvd;

        if (data.unpack(writeMak, bootInfoAck, rsvd) != 0 ||
            !data.fullyUnpacked())
        {
            return ipmi::responseReqDataLenInvalid();
        }
        if (rsvd)
        {
            return ipmi::responseInvalidFieldRequest();
        }
        bootInitiatorAckData &= ~writeMak;
        bootInitiatorAckData |= (writeMak & bootInfoAck);
        log<level::INFO>("ipmiChassisSetSysBootOptions: bootInfo parameter set "
                         "successfully");
        data.trailingOk = true;
        return ipmi::responseSuccess();
    }
    else if (types::enum_cast<BootOptionParameter>(parameterSelector) ==
             BootOptionParameter::bootFlagValidClr)
    {
        uint5_t bootFlagValidClr;
        uint3_t rsvd;

        if (data.unpack(bootFlagValidClr, rsvd) != 0 || !data.fullyUnpacked())
        {
            return ipmi::responseReqDataLenInvalid();
        }
        if (rsvd)
        {
            return ipmi::responseInvalidFieldRequest();
        }
        // store boot flag valid bits clear value
        bootFlagValidBitClr = static_cast<uint8_t>(bootFlagValidClr);
        log<level::INFO>(
            "ipmiChassisSetSysBootOptions: bootFlagValidBits parameter set "
            "successfully",
            entry("value=0x%x", bootFlagValidBitClr));
        return ipmi::responseSuccess();
    }
    else
    {
        if ((parameterSelector >= static_cast<uint7_t>(oemParmStart)) &&
            (parameterSelector <= static_cast<uint7_t>(oemParmEnd)))
        {
            if (types::enum_cast<BootOptionParameter>(parameterSelector) ==
                BootOptionParameter::opalNetworkSettings)
            {
                ipmi::Cc ret = setHostNetworkData(data);
                if (ret != ipmi::ccSuccess)
                {
                    log<level::ERR>("ipmiChassisSetSysBootOptions: Error in "
                                    "setHostNetworkData");
                    data.trailingOk = true;
                    return ipmi::response(ret);
                }
                data.trailingOk = true;
                return ipmi::responseSuccess();
            }
            else
            {
                log<level::ERR>(
                    "ipmiChassisSetSysBootOptions: Unsupported parameters",
                    entry("PARAM=0x%x",
                          static_cast<uint8_t>(parameterSelector)));
                data.trailingOk = true;
                return ipmi::responseParmNotSupported();
            }
        }
        data.trailingOk = true;
        return ipmi::responseParmNotSupported();
    }
    return ipmi::responseSuccess();
}

/** @brief implements Get POH counter command
 *  @parameter
 *   -  none
 *  @returns IPMI completion code plus response data
 *   - minPerCount - Minutes per count
 *   - counterReading - counter reading
 */
ipmi::RspType<uint8_t, // Minutes per count
              uint32_t // Counter reading
              >
    ipmiGetPOHCounter()
{
    // sd_bus error
    try
    {
        return ipmi::responseSuccess(static_cast<uint8_t>(poh::minutesPerCount),
                                     getPOHCounter());
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(e.what());
        return ipmi::responseUnspecifiedError();
    }
}

ipmi::RspType<uint3_t, // policy support
              uint5_t  // reserved
              >
    ipmiChassisSetPowerRestorePolicy(boost::asio::yield_context yield,
                                     uint3_t policy, uint5_t reserved)
{
    power_policy::DbusValue value =
        power_policy::RestorePolicy::Policy::AlwaysOff;

    if (reserved || (policy > power_policy::noChange))
    {
        phosphor::logging::log<level::ERR>(
            "Reserved request parameter",
            entry("REQ=0x%x", static_cast<int>(policy)));
        return ipmi::responseInvalidFieldRequest();
    }

    if (policy == power_policy::noChange)
    {
        // just return the supported policy
        return ipmi::responseSuccess(power_policy::allSupport, reserved);
    }

    for (auto const& it : power_policy::dbusToIpmi)
    {
        if (it.second == policy)
        {
            value = it.first;
            break;
        }
    }

    try
    {
        settings::Objects& objects = chassis::internal::cache::getObjects();
        const settings::Path& powerRestoreSetting =
            objects.map.at(chassis::internal::powerRestoreIntf).front();
        std::variant<std::string> property = convertForMessage(value);

        auto sdbusp = getSdBus();
        boost::system::error_code ec;
        sdbusp->yield_method_call<void>(
            yield, ec,
            objects
                .service(powerRestoreSetting,
                         chassis::internal::powerRestoreIntf)
                .c_str(),
            powerRestoreSetting, ipmi::PROP_INTF, "Set",
            chassis::internal::powerRestoreIntf, "PowerRestorePolicy",
            property);
        if (ec)
        {
            phosphor::logging::log<level::ERR>("Unspecified Error");
            return ipmi::responseUnspecifiedError();
        }
    }
    catch (const InternalFailure& e)
    {
        chassis::internal::cache::objectsPtr.reset();
        report<InternalFailure>();
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(power_policy::allSupport, reserved);
}

ipmi::RspType<> ipmiSetFrontPanelButtonEnables(ipmi::Context::ptr ctx,
                                               bool disablePowerButton,
                                               bool disableResetButton, bool,
                                               bool, uint4_t)
{
    using namespace chassis::internal;

    // set power button Enabled property
    bool success = setButtonEnabled(ctx, powerButtonPath, powerButtonIntf,
                                    !disablePowerButton);

    // set reset button Enabled property
    success &= setButtonEnabled(ctx, resetButtonPath, resetButtonIntf,
                                !disableResetButton);

    if (!success)
    {
        // not all buttons were successfully set
        return ipmi::responseUnspecifiedError();
    }
    return ipmi::responseSuccess();
}

void register_netfn_chassis_functions()
{
    createIdentifyTimer();

    // Get Chassis Capabilities
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnChassis,
                          ipmi::chassis::cmdGetChassisCapabilities,
                          ipmi::Privilege::User, ipmiGetChassisCap);

    // Set Front Panel Button Enables
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnChassis,
                          ipmi::chassis::cmdSetFrontPanelButtonEnables,
                          ipmi::Privilege::Admin,
                          ipmiSetFrontPanelButtonEnables);

    // Set Chassis Capabilities
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnChassis,
                          ipmi::chassis::cmdSetChassisCapabilities,
                          ipmi::Privilege::User, ipmiSetChassisCap);

    // <Get System Boot Options>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnChassis,
                          ipmi::chassis::cmdGetSystemBootOptions,
                          ipmi::Privilege::Operator,
                          ipmiChassisGetSysBootOptions);

    // <Get Chassis Status>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnChassis,
                          ipmi::chassis::cmdGetChassisStatus,
                          ipmi::Privilege::User, ipmiGetChassisStatus);

    // <Chassis Get System Restart Cause>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnChassis,
                          ipmi::chassis::cmdGetSystemRestartCause,
                          ipmi::Privilege::User, ipmiGetSystemRestartCause);

    // <Chassis Control>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnChassis,
                          ipmi::chassis::cmdChassisControl,
                          ipmi::Privilege::Operator, ipmiChassisControl);

    // <Chassis Identify>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnChassis,
                          ipmi::chassis::cmdChassisIdentify,
                          ipmi::Privilege::Operator, ipmiChassisIdentify);

    // <Set System Boot Options>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnChassis,
                          ipmi::chassis::cmdSetSystemBootOptions,
                          ipmi::Privilege::Operator,
                          ipmiChassisSetSysBootOptions);

    // <Get POH Counter>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnChassis,
                          ipmi::chassis::cmdGetPohCounter,
                          ipmi::Privilege::User, ipmiGetPOHCounter);

    // <Set Power Restore Policy>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnChassis,
                          ipmi::chassis::cmdSetPowerRestorePolicy,
                          ipmi::Privilege::Operator,
                          ipmiChassisSetPowerRestorePolicy);
}
