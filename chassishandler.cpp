#include "config.h"

#include "chassishandler.hpp"

#include "ipmid.hpp"
#include "settings.hpp"
#include "types.hpp"
#include "utils.hpp"

#include <arpa/inet.h>
#include <endian.h>
#include <ipmid/api.h>
#include <limits.h>
#include <mapper.h>
#include <netinet/in.h>

#include <array>
#include <chrono>
#include <cstring>
#include <fstream>
#include <future>
#include <map>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/message/types.hpp>
#include <sdbusplus/server/object.hpp>
#include <sdbusplus/timer.hpp>
#include <sstream>
#include <string>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/Control/Boot/Mode/server.hpp>
#include <xyz/openbmc_project/Control/Boot/Source/server.hpp>
#include <xyz/openbmc_project/Control/Power/RestorePolicy/server.hpp>
#include <xyz/openbmc_project/State/Host/server.hpp>
#include <xyz/openbmc_project/State/PowerOnHours/server.hpp>

#if __has_include(<filesystem>)
#include <filesystem>
#elif __has_include(<experimental/filesystem>)
#include <experimental/filesystem>
namespace std
{
// splice experimental::filesystem into std
namespace filesystem = std::experimental::filesystem;
} // namespace std
#else
#error filesystem not available
#endif

// Defines
#define SET_PARM_VERSION 0x01
#define SET_PARM_BOOT_FLAGS_PERMANENT 0x40
#define SET_PARM_BOOT_FLAGS_VALID_ONE_TIME 0x80
#define SET_PARM_BOOT_FLAGS_VALID_PERMANENT 0xC0

std::unique_ptr<phosphor::Timer> identifyTimer
    __attribute__((init_priority(101)));

constexpr size_t SIZE_MAC = 18;
constexpr size_t SIZE_BOOT_OPTION = (uint8_t)
    BootOptionResponseSize::OPAL_NETWORK_SETTINGS; // Maximum size of the boot
                                                   // option parametrs
constexpr size_t SIZE_PREFIX = 7;
constexpr size_t MAX_PREFIX_VALUE = 32;
constexpr size_t SIZE_COOKIE = 4;
constexpr size_t SIZE_VERSION = 2;
constexpr size_t DEFAULT_IDENTIFY_TIME_OUT = 15;

// PetiBoot-Specific
static constexpr uint8_t net_conf_initial_bytes[] = {0x80, 0x21, 0x70, 0x62,
                                                     0x21, 0x00, 0x01, 0x06};

static constexpr size_t COOKIE_OFFSET = 1;
static constexpr size_t VERSION_OFFSET = 5;
static constexpr size_t ADDR_SIZE_OFFSET = 8;
static constexpr size_t MAC_OFFSET = 9;
static constexpr size_t ADDRTYPE_OFFSET = 16;
static constexpr size_t IPADDR_OFFSET = 17;

static constexpr size_t encIdentifyObjectsSize = 1;
static constexpr size_t chassisIdentifyReqLength = 2;
static constexpr size_t identifyIntervalPos = 0;
static constexpr size_t forceIdentifyPos = 1;

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
static constexpr auto pOHCounterProperty = "POHCounter";
static constexpr auto match = "chassis0";
const static constexpr char chassisCapIntf[] =
    "xyz.openbmc_project.Control.ChassisCapabilities";
const static constexpr char chassisCapFlagsProp[] = "CapabilitiesFlags";
const static constexpr char chassisFRUDevAddrProp[] = "FRUDeviceAddress";
const static constexpr char chassisSDRDevAddrProp[] = "SDRDeviceAddress";
const static constexpr char chassisSELDevAddrProp[] = "SELDeviceAddress";
const static constexpr char chassisSMDevAddrProp[] = "SMDeviceAddress";
const static constexpr char chassisBridgeDevAddrProp[] = "BridgeDeviceAddress";
static constexpr uint8_t chassisCapFlagMask = 0x0f;
static constexpr uint8_t chassisCapAddrMask = 0xfe;

typedef struct
{
    uint8_t cap_flags;
    uint8_t fru_info_dev_addr;
    uint8_t sdr_dev_addr;
    uint8_t sel_dev_addr;
    uint8_t system_management_dev_addr;
    uint8_t bridge_dev_addr;
} __attribute__((packed)) ipmi_chassis_cap_t;

typedef struct
{
    uint8_t cur_power_state;
    uint8_t last_power_event;
    uint8_t misc_power_state;
    uint8_t front_panel_button_cap_status;
} __attribute__((packed)) ipmi_get_chassis_status_t;

/**
 * @struct Get POH counter command response data
 */
struct GetPOHCountResponse
{
    uint8_t minPerCount;       ///< Minutes per count
    uint8_t counterReading[4]; ///< Counter reading
} __attribute__((packed));

// Phosphor Host State manager
namespace State = sdbusplus::xyz::openbmc_project::State::server;

namespace fs = std::filesystem;

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using namespace sdbusplus::xyz::openbmc_project::Control::Boot::server;
namespace variant_ns = sdbusplus::message::variant_ns;

namespace chassis
{
namespace internal
{

constexpr auto bootModeIntf = "xyz.openbmc_project.Control.Boot.Mode";
constexpr auto bootSourceIntf = "xyz.openbmc_project.Control.Boot.Source";
constexpr auto powerRestoreIntf =
    "xyz.openbmc_project.Control.Power.RestorePolicy";
sdbusplus::bus::bus dbus(ipmid_get_sd_bus_connection());

namespace cache
{

settings::Objects objects(dbus,
                          {bootModeIntf, bootSourceIntf, powerRestoreIntf});

} // namespace cache
} // namespace internal
} // namespace chassis

namespace poh
{

constexpr auto minutesPerCount = 60;

} // namespace poh

struct get_sys_boot_options_t
{
    uint8_t parameter;
    uint8_t set;
    uint8_t block;
} __attribute__((packed));

struct get_sys_boot_options_response_t
{
    uint8_t version;
    uint8_t parm;
    uint8_t data[SIZE_BOOT_OPTION];
} __attribute__((packed));

struct set_sys_boot_options_t
{
    uint8_t parameter;
    uint8_t data[SIZE_BOOT_OPTION];
} __attribute__((packed));

int getHostNetworkData(get_sys_boot_options_response_t* respptr)
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

        sdbusplus::bus::bus bus(ipmid_get_sd_bus_connection());

        auto ipObjectInfo = ipmi::getDbusObject(bus, IP_INTERFACE,
                                                SETTINGS_ROOT, SETTINGS_MATCH);

        auto macObjectInfo = ipmi::getDbusObject(bus, MAC_INTERFACE,
                                                 SETTINGS_ROOT, SETTINGS_MATCH);

        properties = ipmi::getAllDbusProperties(
            bus, ipObjectInfo.second, ipObjectInfo.first, IP_INTERFACE);
        auto variant = ipmi::getDbusProperty(bus, macObjectInfo.second,
                                             macObjectInfo.first, MAC_INTERFACE,
                                             "MACAddress");

        auto ipAddress = variant_ns::get<std::string>(properties["Address"]);

        auto gateway = variant_ns::get<std::string>(properties["Gateway"]);

        auto prefix = variant_ns::get<uint8_t>(properties["PrefixLength"]);

        uint8_t isStatic =
            (variant_ns::get<std::string>(properties["Origin"]) ==
             "xyz.openbmc_project.Network.IP.AddressOrigin.Static")
                ? 1
                : 0;

        auto MACAddress = variant_ns::get<std::string>(variant);

        // it is expected here that we should get the valid data
        // but we may also get the default values.
        // Validation of the data is done by settings.
        //
        // if mac address is default mac address then
        // don't send blank override.
        if ((MACAddress == ipmi::network::DEFAULT_MAC_ADDRESS))
        {
            std::memset(respptr->data, 0, SIZE_BOOT_OPTION);
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
                std::memset(respptr->data, 0, SIZE_BOOT_OPTION);
                rc = -1;
                return rc;
            }
        }

        sscanf(
            MACAddress.c_str(), ipmi::network::MAC_ADDRESS_FORMAT,
            (respptr->data + MAC_OFFSET), (respptr->data + MAC_OFFSET + 1),
            (respptr->data + MAC_OFFSET + 2), (respptr->data + MAC_OFFSET + 3),
            (respptr->data + MAC_OFFSET + 4), (respptr->data + MAC_OFFSET + 5));

        respptr->data[MAC_OFFSET + 6] = 0x00;

        std::memcpy(respptr->data + ADDRTYPE_OFFSET, &isStatic,
                    sizeof(isStatic));

        uint8_t addressFamily =
            (variant_ns::get<std::string>(properties["Type"]) ==
             "xyz.openbmc_project.Network.IP.Protocol.IPv4")
                ? AF_INET
                : AF_INET6;

        addrSize = (addressFamily == AF_INET)
                       ? ipmi::network::IPV4_ADDRESS_SIZE_BYTE
                       : ipmi::network::IPV6_ADDRESS_SIZE_BYTE;

        // ipaddress and gateway would be in IPv4 format
        inet_pton(addressFamily, ipAddress.c_str(),
                  (respptr->data + IPADDR_OFFSET));

        uint8_t prefixOffset = IPADDR_OFFSET + addrSize;

        std::memcpy(respptr->data + prefixOffset, &prefix, sizeof(prefix));

        uint8_t gatewayOffset = prefixOffset + sizeof(decltype(prefix));

        inet_pton(addressFamily, gateway.c_str(),
                  (respptr->data + gatewayOffset));
    }
    catch (InternalFailure& e)
    {
        commit<InternalFailure>();
        std::memset(respptr->data, 0, SIZE_BOOT_OPTION);
        rc = -1;
        return rc;
    }

    // PetiBoot-Specific
    // If success then copy the first 9 bytes to the data
    std::memcpy(respptr->data, net_conf_initial_bytes,
                sizeof(net_conf_initial_bytes));

    std::memcpy(respptr->data + ADDR_SIZE_OFFSET, &addrSize, sizeof(addrSize));

#ifdef _IPMI_DEBUG_
    std::printf("\n===Printing the IPMI Formatted Data========\n");

    for (uint8_t pos = 0; pos < index; pos++)
    {
        std::printf("%02x ", respptr->data[pos]);
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

int setHostNetworkData(set_sys_boot_options_t* reqptr)
{
    using namespace std::string_literals;
    std::string host_network_config;
    char mac[]{"00:00:00:00:00:00"};
    std::string ipAddress, gateway;
    char addrOrigin{0};
    uint8_t addrSize{0};
    std::string addressOrigin =
        "xyz.openbmc_project.Network.IP.AddressOrigin.DHCP";
    std::string addressType = "xyz.openbmc_project.Network.IP.Protocol.IPv4";
    uint8_t prefix{0};
    uint32_t zeroCookie = 0;
    uint8_t family = AF_INET;

    // cookie starts from second byte
    // version starts from sixth byte

    try
    {
        do
        {
            // cookie ==  0x21 0x70 0x62 0x21
            if (memcmp(&(reqptr->data[COOKIE_OFFSET]),
                       (net_conf_initial_bytes + COOKIE_OFFSET),
                       SIZE_COOKIE) != 0)
            {
                // cookie == 0
                if (memcmp(&(reqptr->data[COOKIE_OFFSET]), &zeroCookie,
                           SIZE_COOKIE) == 0)
                {
                    // need to zero out the network settings.
                    break;
                }

                log<level::ERR>("Invalid Cookie");
                elog<InternalFailure>();
            }

            // vesion == 0x00 0x01
            if (memcmp(&(reqptr->data[VERSION_OFFSET]),
                       (net_conf_initial_bytes + VERSION_OFFSET),
                       SIZE_VERSION) != 0)
            {

                log<level::ERR>("Invalid Version");
                elog<InternalFailure>();
            }

            std::snprintf(
                mac, SIZE_MAC, ipmi::network::MAC_ADDRESS_FORMAT,
                reqptr->data[MAC_OFFSET], reqptr->data[MAC_OFFSET + 1],
                reqptr->data[MAC_OFFSET + 2], reqptr->data[MAC_OFFSET + 3],
                reqptr->data[MAC_OFFSET + 4], reqptr->data[MAC_OFFSET + 5]);

            std::memcpy(&addrOrigin, &(reqptr->data[ADDRTYPE_OFFSET]),
                        sizeof(decltype(addrOrigin)));

            if (addrOrigin)
            {
                addressOrigin =
                    "xyz.openbmc_project.Network.IP.AddressOrigin.Static";
            }

            // Get the address size
            std::memcpy(&addrSize, &reqptr->data[ADDR_SIZE_OFFSET],
                        sizeof(addrSize));

            uint8_t prefixOffset = IPADDR_OFFSET + addrSize;

            std::memcpy(&prefix, &(reqptr->data[prefixOffset]),
                        sizeof(decltype(prefix)));

            uint8_t gatewayOffset = prefixOffset + sizeof(decltype(prefix));

            if (addrSize != ipmi::network::IPV4_ADDRESS_SIZE_BYTE)
            {
                addressType = "xyz.openbmc_project.Network.IP.Protocol.IPv6";
                family = AF_INET6;
            }

            ipAddress =
                getAddrStr(family, reqptr->data, IPADDR_OFFSET, addrSize);

            gateway = getAddrStr(family, reqptr->data, gatewayOffset, addrSize);

        } while (0);

        // Cookie == 0 or it is a valid cookie
        host_network_config += "ipaddress="s + ipAddress + ",prefix="s +
                               std::to_string(prefix) + ",gateway="s + gateway +
                               ",mac="s + mac + ",addressOrigin="s +
                               addressOrigin;

        sdbusplus::bus::bus bus(ipmid_get_sd_bus_connection());

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

        log<level::DEBUG>(
            "Network configuration changed",
            entry("NETWORKCONFIG=%s", host_network_config.c_str()));
    }
    catch (InternalFailure& e)
    {
        commit<InternalFailure>();
        return -1;
    }

    return 0;
}

uint32_t getPOHCounter()
{
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};

    auto chassisStateObj =
        ipmi::getDbusObject(bus, chassisPOHStateIntf, chassisStateRoot, match);

    auto service =
        ipmi::getService(bus, chassisPOHStateIntf, chassisStateObj.first);

    auto propValue =
        ipmi::getDbusProperty(bus, service, chassisStateObj.first,
                              chassisPOHStateIntf, pOHCounterProperty);

    return variant_ns::get<uint32_t>(propValue);
}

ipmi_ret_t ipmi_chassis_wildcard(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                 ipmi_request_t request,
                                 ipmi_response_t response,
                                 ipmi_data_len_t data_len,
                                 ipmi_context_t context)
{
    // Status code.
    ipmi_ret_t rc = IPMI_CC_INVALID;
    *data_len = 0;
    return rc;
}

ipmi_ret_t ipmi_get_chassis_cap(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request,
                                ipmi_response_t response,
                                ipmi_data_len_t data_len,
                                ipmi_context_t context)
{
    // sd_bus error
    ipmi_ret_t rc = IPMI_CC_OK;

    ipmi_chassis_cap_t chassis_cap{};

    if (*data_len != 0)
    {
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *data_len = sizeof(ipmi_chassis_cap_t);

    try
    {
        sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};

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
        ipmi::Value variant = ipmi::getDbusProperty(
            bus, chassisCapObject.second, chassisCapObject.first,
            chassisCapIntf, chassisCapFlagsProp);
        chassis_cap.cap_flags = variant_ns::get<uint8_t>(variant);

        variant = ipmi::getDbusProperty(bus, chassisCapObject.second,
                                        chassisCapObject.first, chassisCapIntf,
                                        chassisFRUDevAddrProp);
        // Chassis FRU info Device Address.
        chassis_cap.fru_info_dev_addr = variant_ns::get<uint8_t>(variant);

        variant = ipmi::getDbusProperty(bus, chassisCapObject.second,
                                        chassisCapObject.first, chassisCapIntf,
                                        chassisSDRDevAddrProp);
        // Chassis SDR Device Address.
        chassis_cap.sdr_dev_addr = variant_ns::get<uint8_t>(variant);

        variant = ipmi::getDbusProperty(bus, chassisCapObject.second,
                                        chassisCapObject.first, chassisCapIntf,
                                        chassisSELDevAddrProp);
        // Chassis SEL Device Address.
        chassis_cap.sel_dev_addr = variant_ns::get<uint8_t>(variant);

        variant = ipmi::getDbusProperty(bus, chassisCapObject.second,
                                        chassisCapObject.first, chassisCapIntf,
                                        chassisSMDevAddrProp);
        // Chassis System Management Device Address.
        chassis_cap.system_management_dev_addr =
            variant_ns::get<uint8_t>(variant);

        variant = ipmi::getDbusProperty(bus, chassisCapObject.second,
                                        chassisCapObject.first, chassisCapIntf,
                                        chassisBridgeDevAddrProp);
        // Chassis Bridge Device Address.
        chassis_cap.bridge_dev_addr = variant_ns::get<uint8_t>(variant);
        uint8_t* respP = reinterpret_cast<uint8_t*>(response);
        uint8_t* chassisP = reinterpret_cast<uint8_t*>(&chassis_cap);
        std::copy(chassisP, chassisP + *data_len, respP);
    }
    catch (std::exception& e)
    {
        log<level::ERR>(e.what());
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        *data_len = 0;
        return rc;
    }

    return rc;
}

ipmi_ret_t ipmi_set_chassis_cap(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request,
                                ipmi_response_t response,
                                ipmi_data_len_t data_len,
                                ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;

    if (*data_len != sizeof(ipmi_chassis_cap_t))
    {
        log<level::ERR>("Unsupported request length",
                        entry("LEN=0x%x", *data_len));
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    ipmi_chassis_cap_t* chassisCap = static_cast<ipmi_chassis_cap_t*>(request);

    *data_len = 0;

    // check input data
    if (0 != (chassisCap->cap_flags & ~chassisCapFlagMask))
    {
        log<level::ERR>("Unsupported request parameter(CAP Flags)",
                        entry("REQ=0x%x", chassisCap->cap_flags));
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    if (0 != (chassisCap->fru_info_dev_addr & ~chassisCapAddrMask))
    {
        log<level::ERR>("Unsupported request parameter(FRU Addr)",
                        entry("REQ=0x%x", chassisCap->fru_info_dev_addr));
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    if (0 != (chassisCap->sdr_dev_addr & ~chassisCapAddrMask))
    {
        log<level::ERR>("Unsupported request parameter(SDR Addr)",
                        entry("REQ=0x%x", chassisCap->sdr_dev_addr));
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    if (0 != (chassisCap->sel_dev_addr & ~chassisCapAddrMask))
    {
        log<level::ERR>("Unsupported request parameter(SEL Addr)",
                        entry("REQ=0x%x", chassisCap->sel_dev_addr));
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    if (0 != (chassisCap->system_management_dev_addr & ~chassisCapAddrMask))
    {
        log<level::ERR>(
            "Unsupported request parameter(SM Addr)",
            entry("REQ=0x%x", chassisCap->system_management_dev_addr));
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    if (0 != (chassisCap->bridge_dev_addr & ~chassisCapAddrMask))
    {
        log<level::ERR>("Unsupported request parameter(Bridge Addr)",
                        entry("REQ=0x%x", chassisCap->bridge_dev_addr));
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    try
    {
        sdbusplus::bus::bus bus(ipmid_get_sd_bus_connection());
        ipmi::DbusObjectInfo chassisCapObject =
            ipmi::getDbusObject(bus, chassisCapIntf);

        ipmi::setDbusProperty(bus, chassisCapObject.second,
                              chassisCapObject.first, chassisCapIntf,
                              chassisCapFlagsProp, chassisCap->cap_flags);

        ipmi::setDbusProperty(bus, chassisCapObject.second,
                              chassisCapObject.first, chassisCapIntf,
                              chassisFRUDevAddrProp,
                              chassisCap->fru_info_dev_addr);

        ipmi::setDbusProperty(bus, chassisCapObject.second,
                              chassisCapObject.first, chassisCapIntf,
                              chassisSDRDevAddrProp, chassisCap->sdr_dev_addr);

        ipmi::setDbusProperty(bus, chassisCapObject.second,
                              chassisCapObject.first, chassisCapIntf,
                              chassisSELDevAddrProp, chassisCap->sel_dev_addr);

        ipmi::setDbusProperty(bus, chassisCapObject.second,
                              chassisCapObject.first, chassisCapIntf,
                              chassisSMDevAddrProp,
                              chassisCap->system_management_dev_addr);

        ipmi::setDbusProperty(bus, chassisCapObject.second,
                              chassisCapObject.first, chassisCapIntf,
                              chassisBridgeDevAddrProp,
                              chassisCap->bridge_dev_addr);
    }
    catch (std::exception& e)
    {
        log<level::ERR>(e.what());
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        return rc;
    }

    return rc;
}

//------------------------------------------
// Calls into Host State Manager Dbus object
//------------------------------------------
int initiate_state_transition(State::Host::Transition transition)
{
    // OpenBMC Host State Manager dbus framework
    constexpr auto HOST_STATE_MANAGER_ROOT = "/xyz/openbmc_project/state/host0";
    constexpr auto HOST_STATE_MANAGER_IFACE = "xyz.openbmc_project.State.Host";
    constexpr auto DBUS_PROPERTY_IFACE = "org.freedesktop.DBus.Properties";
    constexpr auto PROPERTY = "RequestedHostTransition";

    // sd_bus error
    int rc = 0;
    char* busname = NULL;

    // SD Bus error report mechanism.
    sd_bus_error bus_error = SD_BUS_ERROR_NULL;

    // Gets a hook onto either a SYSTEM or SESSION bus
    sd_bus* bus_type = ipmid_get_sd_bus_connection();
    rc = mapper_get_service(bus_type, HOST_STATE_MANAGER_ROOT, &busname);
    if (rc < 0)
    {
        log<level::ERR>(
            "Failed to get bus name",
            entry("ERRNO=0x%X, OBJPATH=%s", -rc, HOST_STATE_MANAGER_ROOT));
        return rc;
    }

    // Convert to string equivalent of the passed in transition enum.
    auto request = State::convertForMessage(transition);

    rc = sd_bus_call_method(bus_type,                // On the system bus
                            busname,                 // Service to contact
                            HOST_STATE_MANAGER_ROOT, // Object path
                            DBUS_PROPERTY_IFACE,     // Interface name
                            "Set",                   // Method to be called
                            &bus_error,              // object to return error
                            nullptr,                 // Response buffer if any
                            "ssv",                   // Takes 3 arguments
                            HOST_STATE_MANAGER_IFACE, PROPERTY, "s",
                            request.c_str());
    if (rc < 0)
    {
        log<level::ERR>("Failed to initiate transition",
                        entry("ERRNO=0x%X, REQUEST=%s", -rc, request.c_str()));
    }
    else
    {
        log<level::INFO>("Transition request initiated successfully");
    }

    sd_bus_error_free(&bus_error);
    free(busname);

    return rc;
}

namespace power_policy
{

using namespace sdbusplus::xyz::openbmc_project::Control::Power::server;
using IpmiValue = uint8_t;
using DbusValue = RestorePolicy::Policy;

std::map<DbusValue, IpmiValue> dbusToIpmi = {
    {RestorePolicy::Policy::AlwaysOff, 0x00},
    {RestorePolicy::Policy::Restore, 0x01},
    {RestorePolicy::Policy::AlwaysOn, 0x02}};

static constexpr uint8_t noChange = 0x03;
static constexpr uint8_t allSupport = 0x01 | 0x02 | 0x04;
static constexpr uint8_t policyBitMask = 0x07;
static constexpr uint8_t setPolicyReqLen = 1;
} // namespace power_policy

//----------------------------------------------------------------------
// Get Chassis Status commands
//----------------------------------------------------------------------
ipmi_ret_t ipmi_get_chassis_status(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                   ipmi_request_t request,
                                   ipmi_response_t response,
                                   ipmi_data_len_t data_len,
                                   ipmi_context_t context)
{
    const char* objname = "/org/openbmc/control/power0";
    const char* intf = "org.openbmc.control.Power";

    sd_bus* bus = NULL;
    sd_bus_message* reply = NULL;
    int r = 0;
    int pgood = 0;
    char* busname = NULL;
    ipmi_ret_t rc = IPMI_CC_OK;
    ipmi_get_chassis_status_t chassis_status{};

    uint8_t s = 0;

    using namespace chassis::internal;
    using namespace chassis::internal::cache;
    using namespace power_policy;

    const auto& powerRestoreSetting = objects.map.at(powerRestoreIntf).front();
    auto method = dbus.new_method_call(
        objects.service(powerRestoreSetting, powerRestoreIntf).c_str(),
        powerRestoreSetting.c_str(), ipmi::PROP_INTF, "Get");
    method.append(powerRestoreIntf, "PowerRestorePolicy");
    auto resp = dbus.call(method);
    if (resp.is_method_error())
    {
        log<level::ERR>("Error in PowerRestorePolicy Get");
        report<InternalFailure>();
        *data_len = 0;
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    sdbusplus::message::variant<std::string> result;
    resp.read(result);
    auto powerRestore = RestorePolicy::convertPolicyFromString(
        variant_ns::get<std::string>(result));

    *data_len = 4;

    bus = ipmid_get_sd_bus_connection();

    r = mapper_get_service(bus, objname, &busname);
    if (r < 0)
    {
        log<level::ERR>("Failed to get bus name", entry("ERRNO=0x%X", -r));
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        goto finish;
    }

    r = sd_bus_get_property(bus, busname, objname, intf, "pgood", NULL, &reply,
                            "i");
    if (r < 0)
    {
        log<level::ERR>("Failed to call sd_bus_get_property",
                        entry("PROPERTY=%s", "pgood"), entry("ERRNO=0x%X", -r),
                        entry("BUS=%s", busname), entry("PATH=%s", objname),
                        entry("INTERFACE=%s", intf));
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        goto finish;
    }

    r = sd_bus_message_read(reply, "i", &pgood);
    if (r < 0)
    {
        log<level::ERR>("Failed to read sensor:", entry("ERRNO=0x%X", -r));
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        goto finish;
    }

    s = dbusToIpmi.at(powerRestore);

    // Current Power State
    // [7] reserved
    // [6..5] power restore policy
    //          00b = chassis stays powered off after AC/mains returns
    //          01b = after AC returns, power is restored to the state that was
    //          in effect when AC/mains was lost.
    //          10b = chassis always powers up after AC/mains returns
    //          11b = unknow
    //        Set to 00b, by observing the hardware behavior.
    //        Do we need to define a dbus property to identify the restore
    //        policy?

    // [4] power control fault
    //       1b = controller attempted to turn system power on or off, but
    //       system did not enter desired state.
    //       Set to 0b, since We don't support it..

    // [3] power fault
    //       1b = fault detected in main power subsystem.
    //       set to 0b. for we don't support it.

    // [2] 1b = interlock (chassis is presently shut down because a chassis
    //       panel interlock switch is active). (IPMI 1.5)
    //       set to 0b,  for we don't support it.

    // [1] power overload
    //      1b = system shutdown because of power overload condition.
    //       set to 0b,  for we don't support it.

    // [0] power is on
    //       1b = system power is on
    //       0b = system power is off(soft-off S4/S5, or mechanical off)

    chassis_status.cur_power_state = ((s & 0x3) << 5) | (pgood & 0x1);

    // Last Power Event
    // [7..5] – reserved
    // [4] – 1b = last ‘Power is on’ state was entered via IPMI command
    // [3] – 1b = last power down caused by power fault
    // [2] – 1b = last power down caused by a power interlock being activated
    // [1] – 1b = last power down caused by a Power overload
    // [0] – 1b = AC failed
    // set to 0x0,  for we don't support these fields.

    chassis_status.last_power_event = 0;

    // Misc. Chassis State
    // [7] – reserved
    // [6] – 1b = Chassis Identify command and state info supported (Optional)
    //       0b = Chassis Identify command support unspecified via this command.
    //       (The Get Command Support command , if implemented, would still
    //       indicate support for the Chassis Identify command)
    // [5..4] – Chassis Identify State. Mandatory when bit[6] =1b, reserved
    // (return
    //          as 00b) otherwise. Returns the present chassis identify state.
    //           Refer to the Chassis Identify command for more info.
    //         00b = chassis identify state = Off
    //         01b = chassis identify state = Temporary(timed) On
    //         10b = chassis identify state = Indefinite On
    //         11b = reserved
    // [3] – 1b = Cooling/fan fault detected
    // [2] – 1b = Drive Fault
    // [1] – 1b = Front Panel Lockout active (power off and reset via chassis
    //       push-buttons disabled.)
    // [0] – 1b = Chassis Intrusion active
    //  set to 0,  for we don't support them.
    chassis_status.misc_power_state = 0;

    //  Front Panel Button Capabilities and disable/enable status(Optional)
    //  set to 0,  for we don't support them.
    chassis_status.front_panel_button_cap_status = 0;

    // Pack the actual response
    std::memcpy(response, &chassis_status, *data_len);

finish:
    free(busname);
    reply = sd_bus_message_unref(reply);

    return rc;
}

//-------------------------------------------------------------
// Send a command to SoftPowerOff application to stop any timer
//-------------------------------------------------------------
int stop_soft_off_timer()
{
    constexpr auto iface = "org.freedesktop.DBus.Properties";
    constexpr auto soft_off_iface = "xyz.openbmc_project.Ipmi.Internal."
                                    "SoftPowerOff";

    constexpr auto property = "ResponseReceived";
    constexpr auto value = "xyz.openbmc_project.Ipmi.Internal."
                           "SoftPowerOff.HostResponse.HostShutdown";

    // Get the system bus where most system services are provided.
    auto bus = ipmid_get_sd_bus_connection();

    // Get the service name
    // TODO openbmc/openbmc#1661 - Mapper refactor
    //
    // See openbmc/openbmc#1743 for some details but high level summary is that
    // for now the code will directly call the soft off interface due to a
    // race condition with mapper usage
    //
    // char *busname = nullptr;
    // auto r = mapper_get_service(bus, SOFTOFF_OBJPATH, &busname);
    // if (r < 0)
    //{
    //    fprintf(stderr, "Failed to get %s bus name: %s\n",
    //            SOFTOFF_OBJPATH, -r);
    //    return r;
    //}

    // No error object or reply expected.
    int rc = sd_bus_call_method(bus, SOFTOFF_BUSNAME, SOFTOFF_OBJPATH, iface,
                                "Set", nullptr, nullptr, "ssv", soft_off_iface,
                                property, "s", value);
    if (rc < 0)
    {
        log<level::ERR>("Failed to set property in SoftPowerOff object",
                        entry("ERRNO=0x%X", -rc));
    }

    // TODO openbmc/openbmc#1661 - Mapper refactor
    // free(busname);
    return rc;
}

//----------------------------------------------------------------------
// Create file to indicate there is no need for softoff notification to host
//----------------------------------------------------------------------
void indicate_no_softoff_needed()
{
    fs::path path{HOST_INBAND_REQUEST_DIR};
    if (!fs::is_directory(path))
    {
        fs::create_directory(path);
    }

    // Add the host instance (default 0 for now) to the file name
    std::string file{HOST_INBAND_REQUEST_FILE};
    auto size = std::snprintf(nullptr, 0, file.c_str(), 0);
    size++; // null
    std::unique_ptr<char[]> buf(new char[size]);
    std::snprintf(buf.get(), size, file.c_str(), 0);

    // Append file name to directory and create it
    path /= buf.get();
    std::ofstream(path.c_str());
}

//----------------------------------------------------------------------
// Chassis Control commands
//----------------------------------------------------------------------
ipmi_ret_t ipmi_chassis_control(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request,
                                ipmi_response_t response,
                                ipmi_data_len_t data_len,
                                ipmi_context_t context)
{
    // Error from power off.
    int rc = 0;

    // No response for this command.
    *data_len = 0;

    // Catch the actual operaton by peeking into request buffer
    uint8_t chassis_ctrl_cmd = *(uint8_t*)request;

    switch (chassis_ctrl_cmd)
    {
        case CMD_POWER_ON:
            rc = initiate_state_transition(State::Host::Transition::On);
            break;
        case CMD_POWER_OFF:
            // This path would be hit in 2 conditions.
            // 1: When user asks for power off using ipmi chassis command 0x04
            // 2: Host asking for power off post shutting down.

            // If it's a host requested power off, then need to nudge Softoff
            // application that it needs to stop the watchdog timer if running.
            // If it is a user requested power off, then this is not really
            // needed. But then we need to differentiate between user and host
            // calling this same command

            // For now, we are going ahead with trying to nudge the soft off and
            // interpret the failure to do so as a non softoff case
            rc = stop_soft_off_timer();

            // Only request the Off transition if the soft power off
            // application is not running
            if (rc < 0)
            {
                // First create a file to indicate to the soft off application
                // that it should not run. Not doing this will result in State
                // manager doing a default soft power off when asked for power
                // off.
                indicate_no_softoff_needed();

                // Now request the shutdown
                rc = initiate_state_transition(State::Host::Transition::Off);
            }
            else
            {
                log<level::INFO>("Soft off is running, so let shutdown target "
                                 "stop the host");
            }
            break;

        case CMD_HARD_RESET:
        case CMD_POWER_CYCLE:
            // SPEC has a section that says certain implementations can trigger
            // PowerOn if power is Off when a command to power cycle is
            // requested

            // First create a file to indicate to the soft off application
            // that it should not run since this is a direct user initiated
            // power reboot request (i.e. a reboot request that is not
            // originating via a soft power off SMS request)
            indicate_no_softoff_needed();

            rc = initiate_state_transition(State::Host::Transition::Reboot);
            break;

        case CMD_SOFT_OFF_VIA_OVER_TEMP:
            // Request Host State Manager to do a soft power off
            rc = initiate_state_transition(State::Host::Transition::Off);
            break;

        default:
        {
            log<level::ERR>("Invalid Chassis Control command",
                            entry("CMD=0x%X", chassis_ctrl_cmd));
            rc = -1;
        }
    }

    return ((rc < 0) ? IPMI_CC_INVALID : IPMI_CC_OK);
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
    auto led =
        dbus.new_method_call(connection.c_str(), identify_led_object_name,
                             "org.freedesktop.DBus.Properties", "Set");
    led.append("xyz.openbmc_project.Led.Group", "Asserted",
               sdbusplus::message::variant<bool>(flag));
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

ipmi_ret_t ipmi_chassis_identify(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                 ipmi_request_t request,
                                 ipmi_response_t response,
                                 ipmi_data_len_t data_len,
                                 ipmi_context_t context)
{
    if (*data_len > chassisIdentifyReqLength)
    {
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    uint8_t identifyInterval =
        *data_len > identifyIntervalPos
            ? (static_cast<uint8_t*>(request))[identifyIntervalPos]
            : DEFAULT_IDENTIFY_TIME_OUT;
    bool forceIdentify =
        (*data_len == chassisIdentifyReqLength)
            ? (static_cast<uint8_t*>(request))[forceIdentifyPos] & 0x01
            : false;

    if (identifyInterval || forceIdentify)
    {
        // stop the timer if already started, for force identify we should
        // not turn off LED
        identifyTimer->stop();
        try
        {
            enclosureIdentifyLed(true);
        }
        catch (const InternalFailure& e)
        {
            report<InternalFailure>();
            return IPMI_CC_RESPONSE_ERROR;
        }

        if (forceIdentify)
        {
            return IPMI_CC_OK;
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
    return IPMI_CC_OK;
}

namespace boot_options
{

using namespace sdbusplus::xyz::openbmc_project::Control::Boot::server;
using IpmiValue = uint8_t;
constexpr auto ipmiDefault = 0;

std::map<IpmiValue, Source::Sources> sourceIpmiToDbus = {
    {0x01, Source::Sources::Network},
    {0x02, Source::Sources::Disk},
    {0x05, Source::Sources::ExternalMedia},
    {ipmiDefault, Source::Sources::Default}};

std::map<IpmiValue, Mode::Modes> modeIpmiToDbus = {
    {0x03, Mode::Modes::Safe},
    {0x06, Mode::Modes::Setup},
    {ipmiDefault, Mode::Modes::Regular}};

std::map<Source::Sources, IpmiValue> sourceDbusToIpmi = {
    {Source::Sources::Network, 0x01},
    {Source::Sources::Disk, 0x02},
    {Source::Sources::ExternalMedia, 0x05},
    {Source::Sources::Default, ipmiDefault}};

std::map<Mode::Modes, IpmiValue> modeDbusToIpmi = {
    {Mode::Modes::Safe, 0x03},
    {Mode::Modes::Setup, 0x06},
    {Mode::Modes::Regular, ipmiDefault}};

} // namespace boot_options

/** @brief Set the property value for boot source
 *  @param[in] source - boot source value
 *  @return On failure return IPMI error.
 */
static ipmi_ret_t setBootSource(const Source::Sources& source)
{
    using namespace chassis::internal;
    using namespace chassis::internal::cache;
    sdbusplus::message::variant<std::string> property =
        convertForMessage(source);
    auto bootSetting = settings::boot::setting(objects, bootSourceIntf);
    const auto& bootSourceSetting = std::get<settings::Path>(bootSetting);
    auto method = dbus.new_method_call(
        objects.service(bootSourceSetting, bootSourceIntf).c_str(),
        bootSourceSetting.c_str(), ipmi::PROP_INTF, "Set");
    method.append(bootSourceIntf, "BootSource", property);
    auto reply = dbus.call(method);
    if (reply.is_method_error())
    {
        log<level::ERR>("Error in BootSource Set");
        report<InternalFailure>();
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    return IPMI_CC_OK;
}

/** @brief Set the property value for boot mode
 *  @param[in] mode - boot mode value
 *  @return On failure return IPMI error.
 */
static ipmi_ret_t setBootMode(const Mode::Modes& mode)
{
    using namespace chassis::internal;
    using namespace chassis::internal::cache;
    sdbusplus::message::variant<std::string> property = convertForMessage(mode);
    auto bootSetting = settings::boot::setting(objects, bootModeIntf);
    const auto& bootModeSetting = std::get<settings::Path>(bootSetting);
    auto method = dbus.new_method_call(
        objects.service(bootModeSetting, bootModeIntf).c_str(),
        bootModeSetting.c_str(), ipmi::PROP_INTF, "Set");
    method.append(bootModeIntf, "BootMode", property);
    auto reply = dbus.call(method);
    if (reply.is_method_error())
    {
        log<level::ERR>("Error in BootMode Set");
        report<InternalFailure>();
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    return IPMI_CC_OK;
}

ipmi_ret_t ipmi_chassis_get_sys_boot_options(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                             ipmi_request_t request,
                                             ipmi_response_t response,
                                             ipmi_data_len_t data_len,
                                             ipmi_context_t context)
{
    using namespace boot_options;
    ipmi_ret_t rc = IPMI_CC_PARM_NOT_SUPPORTED;
    char* p = NULL;
    get_sys_boot_options_response_t* resp =
        (get_sys_boot_options_response_t*)response;
    get_sys_boot_options_t* reqptr = (get_sys_boot_options_t*)request;
    IpmiValue bootOption = ipmiDefault;

    std::memset(resp, 0, sizeof(*resp));
    resp->version = SET_PARM_VERSION;
    resp->parm = 5;
    resp->data[0] = SET_PARM_BOOT_FLAGS_VALID_ONE_TIME;

    /*
     * Parameter #5 means boot flags. Please refer to 28.13 of ipmi doc.
     * This is the only parameter used by petitboot.
     */
    if (reqptr->parameter ==
        static_cast<uint8_t>(BootOptionParameter::BOOT_FLAGS))
    {

        *data_len = static_cast<uint8_t>(BootOptionResponseSize::BOOT_FLAGS);
        using namespace chassis::internal;
        using namespace chassis::internal::cache;

        try
        {
            auto bootSetting = settings::boot::setting(objects, bootSourceIntf);
            const auto& bootSourceSetting =
                std::get<settings::Path>(bootSetting);
            auto oneTimeEnabled =
                std::get<settings::boot::OneTimeEnabled>(bootSetting);
            auto method = dbus.new_method_call(
                objects.service(bootSourceSetting, bootSourceIntf).c_str(),
                bootSourceSetting.c_str(), ipmi::PROP_INTF, "Get");
            method.append(bootSourceIntf, "BootSource");
            auto reply = dbus.call(method);
            if (reply.is_method_error())
            {
                log<level::ERR>("Error in BootSource Get");
                report<InternalFailure>();
                *data_len = 0;
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
            sdbusplus::message::variant<std::string> result;
            reply.read(result);
            auto bootSource = Source::convertSourcesFromString(
                variant_ns::get<std::string>(result));

            bootSetting = settings::boot::setting(objects, bootModeIntf);
            const auto& bootModeSetting = std::get<settings::Path>(bootSetting);
            method = dbus.new_method_call(
                objects.service(bootModeSetting, bootModeIntf).c_str(),
                bootModeSetting.c_str(), ipmi::PROP_INTF, "Get");
            method.append(bootModeIntf, "BootMode");
            reply = dbus.call(method);
            if (reply.is_method_error())
            {
                log<level::ERR>("Error in BootMode Get");
                report<InternalFailure>();
                *data_len = 0;
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
            reply.read(result);
            auto bootMode = Mode::convertModesFromString(
                variant_ns::get<std::string>(result));

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
            resp->data[1] = (bootOption << 2);

            resp->data[0] = oneTimeEnabled
                                ? SET_PARM_BOOT_FLAGS_VALID_ONE_TIME
                                : SET_PARM_BOOT_FLAGS_VALID_PERMANENT;

            rc = IPMI_CC_OK;
        }
        catch (InternalFailure& e)
        {
            report<InternalFailure>();
            *data_len = 0;
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
    }
    else if (reqptr->parameter ==
             static_cast<uint8_t>(BootOptionParameter::OPAL_NETWORK_SETTINGS))
    {

        *data_len =
            static_cast<uint8_t>(BootOptionResponseSize::OPAL_NETWORK_SETTINGS);

        resp->parm =
            static_cast<uint8_t>(BootOptionParameter::OPAL_NETWORK_SETTINGS);

        int ret = getHostNetworkData(resp);

        if (ret < 0)
        {

            log<level::ERR>(
                "getHostNetworkData failed for get_sys_boot_options.");
            rc = IPMI_CC_UNSPECIFIED_ERROR;
        }
        else
            rc = IPMI_CC_OK;
    }

    else
    {
        log<level::ERR>("Unsupported parameter",
                        entry("PARAM=0x%x", reqptr->parameter));
    }

    if (p)
        free(p);

    if (rc == IPMI_CC_OK)
    {
        *data_len += 2;
    }

    return rc;
}

ipmi_ret_t ipmi_chassis_set_sys_boot_options(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                             ipmi_request_t request,
                                             ipmi_response_t response,
                                             ipmi_data_len_t data_len,
                                             ipmi_context_t context)
{
    using namespace boot_options;
    ipmi_ret_t rc = IPMI_CC_OK;
    set_sys_boot_options_t* reqptr = (set_sys_boot_options_t*)request;

    std::printf("IPMI SET_SYS_BOOT_OPTIONS reqptr->parameter =[%d]\n",
                reqptr->parameter);

    // This IPMI command does not have any resposne data
    *data_len = 0;

    /*  000101
     * Parameter #5 means boot flags. Please refer to 28.13 of ipmi doc.
     * This is the only parameter used by petitboot.
     */

    if (reqptr->parameter == (uint8_t)BootOptionParameter::BOOT_FLAGS)
    {
        IpmiValue bootOption = ((reqptr->data[1] & 0x3C) >> 2);
        using namespace chassis::internal;
        using namespace chassis::internal::cache;
        auto oneTimeEnabled = false;
        constexpr auto enabledIntf = "xyz.openbmc_project.Object.Enable";
        constexpr auto oneTimePath =
            "/xyz/openbmc_project/control/host0/boot/one_time";

        try
        {
            bool permanent =
                (reqptr->data[0] & SET_PARM_BOOT_FLAGS_PERMANENT) ==
                SET_PARM_BOOT_FLAGS_PERMANENT;

            auto bootSetting = settings::boot::setting(objects, bootSourceIntf);

            oneTimeEnabled =
                std::get<settings::boot::OneTimeEnabled>(bootSetting);

            /*
             * Check if the current boot setting is onetime or permanent, if the
             * request in the command is otherwise, then set the "Enabled"
             * property in one_time object path to 'True' to indicate onetime
             * and 'False' to indicate permanent.
             *
             * Once the onetime/permanent setting is applied, then the bootMode
             * and bootSource is updated for the corresponding object.
             */
            if ((permanent && oneTimeEnabled) ||
                (!permanent && !oneTimeEnabled))
            {
                auto service = ipmi::getService(dbus, enabledIntf, oneTimePath);

                ipmi::setDbusProperty(dbus, service, oneTimePath, enabledIntf,
                                      "Enabled", !permanent);
            }

            auto modeItr = modeIpmiToDbus.find(bootOption);
            auto sourceItr = sourceIpmiToDbus.find(bootOption);
            if (sourceIpmiToDbus.end() != sourceItr)
            {
                rc = setBootSource(sourceItr->second);
                if (rc != IPMI_CC_OK)
                {
                    *data_len = 0;
                    return rc;
                }
                // If a set boot device is mapping to a boot source, then reset
                // the boot mode D-Bus property to default.
                // This way the ipmid code can determine which property is not
                // at the default value
                if (sourceItr->second != Source::Sources::Default)
                {
                    setBootMode(Mode::Modes::Regular);
                }
            }
            if (modeIpmiToDbus.end() != modeItr)
            {
                rc = setBootMode(modeItr->second);
                if (rc != IPMI_CC_OK)
                {
                    *data_len = 0;
                    return rc;
                }
                // If a set boot device is mapping to a boot mode, then reset
                // the boot source D-Bus property to default.
                // This way the ipmid code can determine which property is not
                // at the default value
                if (modeItr->second != Mode::Modes::Regular)
                {
                    setBootSource(Source::Sources::Default);
                }
            }
        }
        catch (InternalFailure& e)
        {
            report<InternalFailure>();
            *data_len = 0;
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
    }
    else if (reqptr->parameter ==
             (uint8_t)BootOptionParameter::OPAL_NETWORK_SETTINGS)
    {

        int ret = setHostNetworkData(reqptr);
        if (ret < 0)
        {
            log<level::ERR>(
                "setHostNetworkData failed for set_sys_boot_options");
            rc = IPMI_CC_UNSPECIFIED_ERROR;
        }
    }
    else if (reqptr->parameter ==
             static_cast<uint8_t>(BootOptionParameter::BOOT_INFO))
    {
        // Handle parameter #4 and return command completed normally
        // (IPMI_CC_OK). There is no implementation in OpenBMC for this
        // parameter. This is added to support the ipmitool command `chassis
        // bootdev` which sends set on parameter #4, before setting the boot
        // flags.
        rc = IPMI_CC_OK;
    }
    else
    {
        log<level::ERR>("Unsupported parameter",
                        entry("PARAM=0x%x", reqptr->parameter));
        rc = IPMI_CC_PARM_NOT_SUPPORTED;
    }

    return rc;
}

ipmi_ret_t ipmiGetPOHCounter(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    // sd_bus error
    ipmi_ret_t rc = IPMI_CC_OK;

    auto resptr = reinterpret_cast<GetPOHCountResponse*>(response);

    try
    {
        auto pohCounter = getPOHCounter();
        resptr->counterReading[0] = pohCounter;
        resptr->counterReading[1] = pohCounter >> 8;
        resptr->counterReading[2] = pohCounter >> 16;
        resptr->counterReading[3] = pohCounter >> 24;
    }
    catch (std::exception& e)
    {
        log<level::ERR>(e.what());
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    resptr->minPerCount = poh::minutesPerCount;
    *data_len = sizeof(GetPOHCountResponse);

    return rc;
}

ipmi_ret_t ipmi_chassis_set_power_restore_policy(
    ipmi_netfn_t netfn, ipmi_cmd_t cmd, ipmi_request_t request,
    ipmi_response_t response, ipmi_data_len_t data_len, ipmi_context_t context)
{
    auto* reqptr = reinterpret_cast<uint8_t*>(request);
    auto* resptr = reinterpret_cast<uint8_t*>(response);
    uint8_t reqPolicy = 0;

    power_policy::DbusValue value =
        power_policy::RestorePolicy::Policy::AlwaysOff;

    if (*data_len != power_policy::setPolicyReqLen)
    {
        phosphor::logging::log<level::ERR>("Unsupported request length",
                                           entry("LEN=0x%x", *data_len));
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    if (*reqptr > power_policy::noChange)
    {
        phosphor::logging::log<level::ERR>("Reserved request parameter",
                                           entry("REQ=0x%x", *reqptr));
        *data_len = 0;
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    reqPolicy = *reqptr & power_policy::policyBitMask;
    if (reqPolicy == power_policy::noChange)
    {
        // just return the supported policy
        *resptr = power_policy::allSupport;
        *data_len = power_policy::setPolicyReqLen;
        return IPMI_CC_OK;
    }

    for (auto const& it : power_policy::dbusToIpmi)
    {
        if (it.second == reqPolicy)
        {
            value = it.first;
            break;
        }
    }

    try
    {
        const settings::Path& powerRestoreSetting =
            chassis::internal::cache::objects.map
                .at(chassis::internal::powerRestoreIntf)
                .front();
        sdbusplus::message::variant<std::string> property =
            convertForMessage(value);

        auto method = chassis::internal::dbus.new_method_call(
            chassis::internal::cache::objects
                .service(powerRestoreSetting,
                         chassis::internal::powerRestoreIntf)
                .c_str(),
            powerRestoreSetting.c_str(), ipmi::PROP_INTF, "Set");

        method.append(chassis::internal::powerRestoreIntf, "PowerRestorePolicy",
                      property);
        auto reply = chassis::internal::dbus.call(method);
        if (reply.is_method_error())
        {
            phosphor::logging::log<level::ERR>("Unspecified Error");
            *data_len = 0;
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
    }
    catch (InternalFailure& e)
    {
        report<InternalFailure>();
        *data_len = 0;
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    *resptr = power_policy::allSupport;
    *data_len = power_policy::setPolicyReqLen;
    return IPMI_CC_OK;
}

void register_netfn_chassis_functions()
{
    createIdentifyTimer();

    // <Wildcard Command>
    ipmi_register_callback(NETFUN_CHASSIS, IPMI_CMD_WILDCARD, NULL,
                           ipmi_chassis_wildcard, PRIVILEGE_USER);

    // Get Chassis Capabilities
    ipmi_register_callback(NETFUN_CHASSIS, IPMI_CMD_GET_CHASSIS_CAP, NULL,
                           ipmi_get_chassis_cap, PRIVILEGE_USER);

    // Set Chassis Capabilities
    ipmi_register_callback(NETFUN_CHASSIS, IPMI_CMD_SET_CHASSIS_CAP, NULL,
                           ipmi_set_chassis_cap, PRIVILEGE_USER);

    // <Get System Boot Options>
    ipmi_register_callback(NETFUN_CHASSIS, IPMI_CMD_GET_SYS_BOOT_OPTIONS, NULL,
                           ipmi_chassis_get_sys_boot_options,
                           PRIVILEGE_OPERATOR);

    // <Get Chassis Status>
    ipmi_register_callback(NETFUN_CHASSIS, IPMI_CMD_CHASSIS_STATUS, NULL,
                           ipmi_get_chassis_status, PRIVILEGE_USER);

    // <Chassis Control>
    ipmi_register_callback(NETFUN_CHASSIS, IPMI_CMD_CHASSIS_CONTROL, NULL,
                           ipmi_chassis_control, PRIVILEGE_OPERATOR);

    // <Chassis Identify>
    ipmi_register_callback(NETFUN_CHASSIS, IPMI_CMD_CHASSIS_IDENTIFY, NULL,
                           ipmi_chassis_identify, PRIVILEGE_OPERATOR);

    // <Set System Boot Options>
    ipmi_register_callback(NETFUN_CHASSIS, IPMI_CMD_SET_SYS_BOOT_OPTIONS, NULL,
                           ipmi_chassis_set_sys_boot_options,
                           PRIVILEGE_OPERATOR);
    // <Get POH Counter>
    ipmi_register_callback(NETFUN_CHASSIS, IPMI_CMD_GET_POH_COUNTER, NULL,
                           ipmiGetPOHCounter, PRIVILEGE_USER);

    // <Set Power Restore Policy>
    ipmi_register_callback(NETFUN_CHASSIS, IPMI_CMD_SET_RESTORE_POLICY, NULL,
                           ipmi_chassis_set_power_restore_policy,
                           PRIVILEGE_OPERATOR);
}
