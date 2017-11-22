#include "chassishandler.h"
#include "host-ipmid/ipmid-api.h"
#include "types.hpp"
#include "ipmid.hpp"
#include "settings.hpp"
#include "utils.hpp"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <mapper.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <limits.h>
#include <string.h>
#include <endian.h>
#include <sstream>
#include <array>
#include <fstream>
#include <future>
#include <experimental/filesystem>
#include <string>
#include <map>

#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <xyz/openbmc_project/State/Host/server.hpp>
#include "xyz/openbmc_project/Common/error.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/Control/Boot/Source/server.hpp>
#include <xyz/openbmc_project/Control/Boot/Mode/server.hpp>
#include <xyz/openbmc_project/Control/Power/RestorePolicy/server.hpp>

#include "config.h"

//Defines
#define SET_PARM_VERSION                     0x01
#define SET_PARM_BOOT_FLAGS_PERMANENT        0x40 //boot flags data1 7th bit on
#define SET_PARM_BOOT_FLAGS_VALID_ONE_TIME   0x80 //boot flags data1 8th bit on
#define SET_PARM_BOOT_FLAGS_VALID_PERMANENT  0xC0 //boot flags data1 7 & 8 bit on

constexpr size_t SIZE_MAC  = 18;
constexpr size_t SIZE_BOOT_OPTION = (uint8_t)BootOptionResponseSize::
        OPAL_NETWORK_SETTINGS;//Maximum size of the boot option parametrs
constexpr size_t SIZE_PREFIX = 7;
constexpr size_t MAX_PREFIX_VALUE = 32;
constexpr size_t SIZE_COOKIE = 4;
constexpr size_t SIZE_VERSION = 2;
constexpr size_t DEFAULT_IDENTIFY_TIME_OUT = 15;

//PetiBoot-Specific
static constexpr uint8_t net_conf_initial_bytes[] = {0x80, 0x21, 0x70, 0x62,
        0x21, 0x00, 0x01, 0x06};

static constexpr size_t COOKIE_OFFSET = 1;
static constexpr size_t VERSION_OFFSET = 5;
static constexpr size_t ADDR_SIZE_OFFSET = 8;
static constexpr size_t MAC_OFFSET = 9;
static constexpr size_t ADDRTYPE_OFFSET = 16;
static constexpr size_t IPADDR_OFFSET = 17;

static std::unique_ptr<std::future<void>> ipmi_chassis_identify_future;
static std::atomic_size_t ipmi_chassis_identify_ref_count(0);


void register_netfn_chassis_functions() __attribute__((constructor));

// Host settings in dbus
// Service name should be referenced by connection name got via object mapper
const char *settings_object_name  =  "/org/openbmc/settings/host0";
const char *settings_intf_name    =  "org.freedesktop.DBus.Properties";
const char *host_intf_name        =  "org.openbmc.settings.Host";

constexpr auto SETTINGS_ROOT = "/";
constexpr auto SETTINGS_MATCH = "host0";

constexpr auto IP_INTERFACE = "xyz.openbmc_project.Network.IP";
constexpr auto MAC_INTERFACE = "xyz.openbmc_project.Network.MACAddress";


typedef struct
{
    uint8_t cap_flags;
    uint8_t fru_info_dev_addr;
    uint8_t sdr_dev_addr;
    uint8_t sel_dev_addr;
    uint8_t system_management_dev_addr;
    uint8_t bridge_dev_addr;
}__attribute__((packed)) ipmi_chassis_cap_t;

typedef struct
{
    uint8_t cur_power_state;
    uint8_t last_power_event;
    uint8_t misc_power_state;
    uint8_t front_panel_button_cap_status;
}__attribute__((packed)) ipmi_get_chassis_status_t;

// Phosphor Host State manager
namespace State = sdbusplus::xyz::openbmc_project::State::server;

namespace fs = std::experimental::filesystem;

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

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

//TODO : Can remove the below function as we have
//       new functions which uses sdbusplus.
//
//       openbmc/openbmc#1489
int dbus_get_property(const char *name, char **buf)
{
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *m = NULL;
    sd_bus *bus = NULL;
    char *temp_buf = NULL;
    char *connection = NULL;
    int r;

    // Get the system bus where most system services are provided.
    bus = ipmid_get_sd_bus_connection();

    r = mapper_get_service(bus, settings_object_name, &connection);
    if (r < 0) {
        fprintf(stderr, "Failed to get %s connection: %s\n",
                settings_object_name, strerror(-r));
        goto finish;
    }

    /*
     * Bus, service, object path, interface and method are provided to call
     * the method.
     * Signatures and input arguments are provided by the arguments at the
     * end.
     */
    r = sd_bus_call_method(bus,
                           connection,                                 /* service to contact */
                           settings_object_name,                       /* object path */
                           settings_intf_name,                         /* interface name */
                           "Get",                                      /* method name */
                           &error,                                     /* object to return error in */
                           &m,                                         /* return message on success */
                           "ss",                                       /* input signature */
                           host_intf_name,                             /* first argument */
                           name);                                      /* second argument */

    if (r < 0) {
        fprintf(stderr, "Failed to issue method call: %s\n", error.message);
        goto finish;
    }

    /*
     * The output should be parsed exactly the same as the output formatting
     * specified.
     */
    r = sd_bus_message_read(m, "v", "s", &temp_buf);
    if (r < 0) {
        fprintf(stderr, "Failed to parse response message: %s\n", strerror(-r));
        goto finish;
    }

    *buf = strdup(temp_buf);
    /*    *buf = (char*) malloc(strlen(temp_buf));
    if (*buf) {
        strcpy(*buf, temp_buf);
    }
     */
    printf("IPMID boot option property get: {%s}.\n", (char *) temp_buf);

finish:
    sd_bus_error_free(&error);
    sd_bus_message_unref(m);
    free(connection);

    return r;
}

//TODO : Can remove the below function as we have
//       new functions which uses sdbusplus.
//
//       openbmc/openbmc#1489

int dbus_set_property(const char * name, const char *value)
{
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *m = NULL;
    sd_bus *bus = NULL;
    char *connection = NULL;
    int r;

    // Get the system bus where most system services are provided.
    bus = ipmid_get_sd_bus_connection();

    r = mapper_get_service(bus, settings_object_name, &connection);
    if (r < 0) {
        fprintf(stderr, "Failed to get %s connection: %s\n",
                settings_object_name, strerror(-r));
        goto finish;
    }

    /*
     * Bus, service, object path, interface and method are provided to call
     * the method.
     * Signatures and input arguments are provided by the arguments at the
     * end.
     */
    r = sd_bus_call_method(bus,
                           connection,                                 /* service to contact */
                           settings_object_name,                       /* object path */
                           settings_intf_name,                         /* interface name */
                           "Set",                                      /* method name */
                           &error,                                     /* object to return error in */
                           &m,                                         /* return message on success */
                           "ssv",                                      /* input signature */
                           host_intf_name,                             /* first argument */
                           name,                                       /* second argument */
                           "s",                                        /* third argument */
                           value);                                     /* fourth argument */

    if (r < 0) {
        fprintf(stderr, "Failed to issue method call: %s\n", error.message);
        goto finish;
    }

    printf("IPMID boot option property set: {%s}.\n", value);

    finish:
    sd_bus_error_free(&error);
    sd_bus_message_unref(m);
    free(connection);

    return r;
}

struct get_sys_boot_options_t {
    uint8_t parameter;
    uint8_t set;
    uint8_t block;
}  __attribute__ ((packed));

struct get_sys_boot_options_response_t {
    uint8_t version;
    uint8_t parm;
    uint8_t data[SIZE_BOOT_OPTION];
}  __attribute__ ((packed));

struct set_sys_boot_options_t {
    uint8_t parameter;
    uint8_t data[SIZE_BOOT_OPTION];
}  __attribute__ ((packed));


int getHostNetworkData(get_sys_boot_options_response_t* respptr)
{
    ipmi::PropertyMap properties;
    int rc = 0;
    uint8_t addrSize = ipmi::network::IPV4_ADDRESS_SIZE_BYTE;

    try
    {
        //TODO There may be cases where an interface is implemented by multiple
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

        properties  = ipmi::getAllDbusProperties(bus, ipObjectInfo.second,
                                            ipObjectInfo.first, IP_INTERFACE);
        auto variant =
            ipmi::getDbusProperty(bus, macObjectInfo.second,
                                  macObjectInfo.first,
                                  MAC_INTERFACE, "MACAddress");

       auto ipAddress = properties["Address"].get<std::string>();

        auto gateway = properties["Gateway"].get<std::string>();

        auto prefix = properties["PrefixLength"].get<uint8_t>();

        uint8_t isStatic = (properties["Origin"].get<std::string>() ==
            "xyz.openbmc_project.Network.IP.AddressOrigin.Static")
                ? 1 : 0;

        auto MACAddress = variant.get<std::string>();

        // it is expected here that we should get the valid data
        // but we may also get the default values.
        // Validation of the data is done by settings.
        //
        // if mac address is default mac address then
        // don't send blank override.
        if ((MACAddress == ipmi::network::DEFAULT_MAC_ADDRESS))
        {
            memset(respptr->data, 0, SIZE_BOOT_OPTION);
            rc = -1;
            return rc;
        }
        // if addr is static then ipaddress,gateway,prefix
        // should not be default one,don't send blank override.
        if (isStatic)
        {
            if((ipAddress == ipmi::network::DEFAULT_ADDRESS) ||
               (gateway == ipmi::network::DEFAULT_ADDRESS) ||
               (!prefix))
            {
                memset(respptr->data, 0, SIZE_BOOT_OPTION);
                rc = -1;
                return rc;
            }
        }

        sscanf(MACAddress.c_str(), ipmi::network::MAC_ADDRESS_FORMAT,
               (respptr->data + MAC_OFFSET),
               (respptr->data + MAC_OFFSET + 1),
               (respptr->data + MAC_OFFSET + 2),
               (respptr->data + MAC_OFFSET + 3),
               (respptr->data + MAC_OFFSET + 4),
               (respptr->data + MAC_OFFSET + 5));

        respptr->data[MAC_OFFSET + 6] = 0x00;

        memcpy(respptr->data + ADDRTYPE_OFFSET, &isStatic,
               sizeof(isStatic));

        uint8_t addressFamily = (properties["Type"].get<std::string>() ==
            "xyz.openbmc_project.Network.IP.Protocol.IPv4") ?
                AF_INET : AF_INET6;

        addrSize = (addressFamily == AF_INET) ?
                       ipmi::network::IPV4_ADDRESS_SIZE_BYTE :
                       ipmi::network::IPV6_ADDRESS_SIZE_BYTE;

        // ipaddress and gateway would be in IPv4 format
        inet_pton(addressFamily, ipAddress.c_str(),
                 (respptr->data + IPADDR_OFFSET));

        uint8_t prefixOffset = IPADDR_OFFSET + addrSize;

        memcpy(respptr->data + prefixOffset, &prefix, sizeof(prefix));

        uint8_t gatewayOffset = prefixOffset + sizeof(decltype(prefix));

        inet_pton(addressFamily, gateway.c_str(),
                 (respptr->data + gatewayOffset));

    }
    catch (InternalFailure& e)
    {
        commit<InternalFailure>();
        memset(respptr->data, 0, SIZE_BOOT_OPTION);
        rc = -1;
        return rc;
    }

    //PetiBoot-Specific
    //If success then copy the first 9 bytes to the data
    memcpy(respptr->data, net_conf_initial_bytes,
           sizeof(net_conf_initial_bytes));

    memcpy(respptr->data + ADDR_SIZE_OFFSET, &addrSize, sizeof(addrSize));

#ifdef _IPMI_DEBUG_
    printf("\n===Printing the IPMI Formatted Data========\n");

    for (uint8_t pos = 0; pos < index; pos++)
    {
        printf("%02x ", respptr->data[pos]);
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

std::string getAddrStr(uint8_t family, uint8_t* data,
                       uint8_t offset, uint8_t addrSize)
{
    char ipAddr[INET6_ADDRSTRLEN] = {};

    switch(family)
    {
        case AF_INET:
        {
            struct sockaddr_in addr4 {};
            memcpy(&addr4.sin_addr.s_addr, &data[offset], addrSize);

            inet_ntop(AF_INET, &addr4.sin_addr,
                      ipAddr, INET_ADDRSTRLEN);

            break;
        }
        case AF_INET6:
        {
            struct sockaddr_in6 addr6 {};
            memcpy(&addr6.sin6_addr.s6_addr, &data[offset], addrSize);

            inet_ntop(AF_INET6, &addr6.sin6_addr,
                      ipAddr, INET6_ADDRSTRLEN);

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
    char mac[] {"00:00:00:00:00:00"};
    std::string ipAddress, gateway;
    char addrOrigin {0};
    uint8_t addrSize {0};
    std::string addressOrigin =
        "xyz.openbmc_project.Network.IP.AddressOrigin.DHCP";
    std::string addressType =
        "xyz.openbmc_project.Network.IP.Protocol.IPv4";
    uint8_t prefix {0};
    uint32_t zeroCookie = 0;
    uint8_t family = AF_INET;

    //cookie starts from second byte
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
                //cookie == 0
                if (memcmp(&(reqptr->data[COOKIE_OFFSET]),
                            &zeroCookie,
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

            snprintf(mac, SIZE_MAC, ipmi::network::MAC_ADDRESS_FORMAT,
                     reqptr->data[MAC_OFFSET],
                     reqptr->data[MAC_OFFSET + 1],
                     reqptr->data[MAC_OFFSET + 2],
                     reqptr->data[MAC_OFFSET + 3],
                     reqptr->data[MAC_OFFSET + 4],
                     reqptr->data[MAC_OFFSET + 5]);

            memcpy(&addrOrigin, &(reqptr->data[ADDRTYPE_OFFSET]),
                   sizeof(decltype(addrOrigin)));

            if (addrOrigin)
            {
                addressOrigin =
                    "xyz.openbmc_project.Network.IP.AddressOrigin.Static";
            }

            // Get the address size
            memcpy(&addrSize ,&reqptr->data[ADDR_SIZE_OFFSET], sizeof(addrSize));

            uint8_t prefixOffset = IPADDR_OFFSET + addrSize;

            memcpy(&prefix, &(reqptr->data[prefixOffset]),
                   sizeof(decltype(prefix)));

            uint8_t gatewayOffset = prefixOffset + sizeof(decltype(prefix));

            if (addrSize != ipmi::network::IPV4_ADDRESS_SIZE_BYTE)
            {
                addressType = "xyz.openbmc_project.Network.IP.Protocol.IPv6";
                family = AF_INET6;
            }

            ipAddress = getAddrStr(family, reqptr->data, IPADDR_OFFSET, addrSize);

            gateway = getAddrStr(family, reqptr->data, gatewayOffset, addrSize);

        } while(0);

        //Cookie == 0 or it is a valid cookie
        host_network_config += "ipaddress="s + ipAddress +
            ",prefix="s + std::to_string(prefix) + ",gateway="s + gateway +
            ",mac="s + mac + ",addressOrigin="s + addressOrigin;


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
        ipmi::setDbusProperty(bus, ipObjectInfo.second, ipObjectInfo.first,
                IP_INTERFACE, "Type",
                std::string("xyz.openbmc_project.Network.IP.Protocol.IPv4"));
        ipmi::setDbusProperty(bus, macObjectInfo.second, macObjectInfo.first,
                MAC_INTERFACE,"MACAddress", std::string(mac));

        log<level::DEBUG>("Network configuration changed",
                entry("NETWORKCONFIG=%s", host_network_config.c_str()));

    }
    catch (InternalFailure& e)
    {
        commit<InternalFailure>();
        return -1;
    }

    return 0;
}

ipmi_ret_t ipmi_chassis_wildcard(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                 ipmi_request_t request,
                                 ipmi_response_t response,
                                 ipmi_data_len_t data_len,
                                 ipmi_context_t context)
{
    printf("Handling CHASSIS WILDCARD Netfn:[0x%X], Cmd:[0x%X]\n",netfn, cmd);
    // Status code.
    ipmi_ret_t rc = IPMI_CC_INVALID;
    *data_len = 0;
    return rc;
}

ipmi_ret_t ipmi_get_chassis_cap(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request, ipmi_response_t response,
                                ipmi_data_len_t data_len, ipmi_context_t context)
{
    // sd_bus error
    ipmi_ret_t rc = IPMI_CC_OK;

    ipmi_chassis_cap_t chassis_cap{};

    *data_len = sizeof(ipmi_chassis_cap_t);

    // TODO: need future work. Get those flag from MRW.

    // capabilities flags
    // [7..4] - reserved
    // [3] – 1b = provides power interlock  (IPM 1.5)
    // [2] – 1b = provides Diagnostic Interrupt (FP NMI)
    // [1] – 1b = provides “Front Panel Lockout” (indicates that the chassis has capabilities
    //            to lock out external power control and reset button or front panel interfaces
    //            and/or detect tampering with those interfaces).
    // [0] -1b = Chassis provides intrusion (physical security) sensor.
    // set to default value 0x0.
    chassis_cap.cap_flags = 0x0;

    // Since we do not have a separate SDR Device/SEL Device/ FRU repository.
    // The 20h was given as those 5 device addresses.
    // Chassis FRU info Device Address
    chassis_cap.fru_info_dev_addr = 0x20;

    // Chassis SDR Device Address
    chassis_cap.sdr_dev_addr = 0x20;

    // Chassis SEL Device Address
    chassis_cap.sel_dev_addr = 0x20;

    // Chassis System Management Device Address
    chassis_cap.system_management_dev_addr = 0x20;

    // Chassis Bridge Device Address.
    chassis_cap.bridge_dev_addr = 0x20;

    memcpy(response, &chassis_cap, *data_len);

    return rc;
}

//------------------------------------------
// Calls into Host State Manager Dbus object
//------------------------------------------
int initiate_state_transition(State::Host::Transition transition)
{
    // OpenBMC Host State Manager dbus framework
    constexpr auto HOST_STATE_MANAGER_ROOT  = "/xyz/openbmc_project/state/host0";
    constexpr auto HOST_STATE_MANAGER_IFACE = "xyz.openbmc_project.State.Host";
    constexpr auto DBUS_PROPERTY_IFACE      = "org.freedesktop.DBus.Properties";
    constexpr auto PROPERTY                 = "RequestedHostTransition";

    // sd_bus error
    int rc = 0;
    char  *busname = NULL;

    // SD Bus error report mechanism.
    sd_bus_error bus_error = SD_BUS_ERROR_NULL;

    // Gets a hook onto either a SYSTEM or SESSION bus
    sd_bus *bus_type = ipmid_get_sd_bus_connection();
    rc = mapper_get_service(bus_type, HOST_STATE_MANAGER_ROOT, &busname);
    if (rc < 0)
    {
        log<level::ERR>("Failed to get bus name",
                        entry("ERROR=%s, OBJPATH=%s",
                              strerror(-rc), HOST_STATE_MANAGER_ROOT));
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
                            HOST_STATE_MANAGER_IFACE,
                            PROPERTY,
                            "s", request.c_str());
    if(rc < 0)
    {
        log<level::ERR>("Failed to initiate transition",
                        entry("ERROR=%s, REQUEST=%s",
                              bus_error.message, request.c_str()));
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

std::map<DbusValue, IpmiValue> dbusToIpmi =
{
    {RestorePolicy::Policy::AlwaysOff, 0x00},
    {RestorePolicy::Policy::Restore, 0x01},
    {RestorePolicy::Policy::AlwaysOn, 0x02}
};

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
    const char  *objname = "/org/openbmc/control/power0";
    const char  *intf = "org.openbmc.control.Power";

    sd_bus *bus = NULL;
    sd_bus_message *reply = NULL;
    int r = 0;
    int pgood = 0;
    char *busname = NULL;
    ipmi_ret_t rc = IPMI_CC_OK;
    ipmi_get_chassis_status_t chassis_status{};

    uint8_t s = 0;

    using namespace chassis::internal;
    using namespace chassis::internal::cache;
    using namespace power_policy;

    const auto& powerRestoreSetting = objects.map.at(powerRestoreIntf).front();
    auto method =
        dbus.new_method_call(
            objects.service(powerRestoreSetting, powerRestoreIntf).c_str(),
            powerRestoreSetting.c_str(),
            ipmi::PROP_INTF,
            "Get");
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
    auto powerRestore =
        RestorePolicy::convertPolicyFromString(result.get<std::string>());

    *data_len = 4;

    bus = ipmid_get_sd_bus_connection();

    r = mapper_get_service(bus, objname, &busname);
    if (r < 0) {
        fprintf(stderr, "Failed to get bus name, return value: %s.\n", strerror(-r));
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        goto finish;
    }

    r = sd_bus_get_property(bus, busname, objname, intf, "pgood", NULL, &reply, "i");
    if (r < 0) {
        fprintf(stderr, "Failed to call sd_bus_get_property:%d,  %s\n", r, strerror(-r));
        fprintf(stderr, "Bus: %s, Path: %s, Interface: %s\n",
                busname, objname, intf);
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        goto finish;
    }

    r = sd_bus_message_read(reply, "i", &pgood);
    if (r < 0) {
        fprintf(stderr, "Failed to read sensor: %s\n", strerror(-r));
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        goto finish;
    }

    printf("pgood is 0x%02x\n", pgood);

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
    //        Do we need to define a dbus property to identify the restore policy?

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

    chassis_status.cur_power_state = ((s & 0x3)<<5) | (pgood & 0x1);

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
    // [5..4] – Chassis Identify State. Mandatory when bit[6] =1b, reserved (return
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
    memcpy(response, &chassis_status, *data_len);

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
    constexpr auto iface            = "org.freedesktop.DBus.Properties";
    constexpr auto soft_off_iface   = "xyz.openbmc_project.Ipmi.Internal."
            "SoftPowerOff";

    constexpr auto property         = "ResponseReceived";
    constexpr auto value            = "xyz.openbmc_project.Ipmi.Internal."
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
    //char *busname = nullptr;
    //auto r = mapper_get_service(bus, SOFTOFF_OBJPATH, &busname);
    //if (r < 0)
    //{
    //    fprintf(stderr, "Failed to get %s bus name: %s\n",
    //            SOFTOFF_OBJPATH, strerror(-r));
    //    return r;
    //}

    // No error object or reply expected.
    int rc = sd_bus_call_method(bus, SOFTOFF_BUSNAME, SOFTOFF_OBJPATH, iface,
                                "Set", nullptr, nullptr, "ssv",
                                soft_off_iface, property, "s", value);
    if (rc < 0)
    {
        fprintf(stderr, "Failed to set property in SoftPowerOff object: %s\n",
                strerror(-rc));
    }

    //TODO openbmc/openbmc#1661 - Mapper refactor
    //free(busname);
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
    auto size = std::snprintf(nullptr,0,file.c_str(),0);
    size++; // null
    std::unique_ptr<char[]> buf(new char[size]);
    std::snprintf(buf.get(),size,file.c_str(),0);

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
    uint8_t chassis_ctrl_cmd = *(uint8_t *)request;
    printf("Chassis Control Command: Operation:[0x%X]\n",chassis_ctrl_cmd);

    switch(chassis_ctrl_cmd)
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
            fprintf(stderr, "Invalid Chassis Control command:[0x%X] received\n",chassis_ctrl_cmd);
            rc = -1;
        }
    }

    return ( (rc < 0) ? IPMI_CC_INVALID : IPMI_CC_OK);
}

ipmi_ret_t ipmi_chassis_identify(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                 ipmi_request_t request,
                                 ipmi_response_t response,
                                 ipmi_data_len_t data_len,
                                 ipmi_context_t context)
{
    if (*data_len > 2)
    {
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    uint8_t identify_interval = *data_len > 0 ?
                                (static_cast<uint8_t*>(request))[0] : DEFAULT_IDENTIFY_TIME_OUT;
    uint8_t force_identify =
        *data_len == 2 ? (static_cast<uint8_t*>(request))[1] & 0x01 : 0;

    size_t ref_id = ++ipmi_chassis_identify_ref_count;

    if (identify_interval || force_identify)
    {
        auto ledOn = chassis::internal::dbus.new_method_call(
                         "xyz.openbmc_project.LED.Controller.identify",
                         "/xyz/openbmc_project/led/physical/identify",
                         "org.freedesktop.DBus.Properties", "Set");
        ledOn.append(
            "xyz.openbmc_project.Led.Physical", "State",
            sdbusplus::message::variant<std::string>(
                "xyz.openbmc_project.Led.Physical.Action.On"));
        auto ledReply = chassis::internal::dbus.call(ledOn);
        if (ledReply.is_method_error())
        {
            fprintf(stderr, "Chassis Identify: Error Setting State On\n");
            return IPMI_CC_RESPONSE_ERROR;
        }
        if (force_identify)
        {
            return IPMI_CC_OK;
        }
    }

    ipmi_chassis_identify_future = std::make_unique<std::future<void>>(
                                       std::async(std::launch::async, [identify_interval, ref_id]
    {
        std::this_thread::sleep_for(
            std::chrono::seconds(identify_interval));

        // another thread was started when we were asleep, exit
        if (ref_id != ipmi_chassis_identify_ref_count)
        {
            return;
        }
        auto ledOff = chassis::internal::dbus.new_method_call(
            "xyz.openbmc_project.LED.Controller.identify",
            "/xyz/openbmc_project/led/physical/identify",
            "org.freedesktop.DBus.Properties", "Set");
        ledOff.append("xyz.openbmc_project.Led.Physical", "State",
        sdbusplus::message::variant<std::string>(
            "xyz.openbmc_project.Led.Physical.Action.Off"));
        auto ledReply = chassis::internal::dbus.call(ledOff);
        if (ledReply.is_method_error())
        {
            fprintf(stderr, "Chassis Identify: Error Setting State Off\n");
        }
    }));
    return IPMI_CC_OK;
}

namespace boot_options
{

using namespace sdbusplus::xyz::openbmc_project::Control::Boot::server;
using IpmiValue = uint8_t;
constexpr auto ipmiDefault = 0;

std::map<IpmiValue, Source::Sources> sourceIpmiToDbus =
{
    {0x01, Source::Sources::Network},
    {0x02, Source::Sources::Disk},
    {0x05, Source::Sources::ExternalMedia},
    {ipmiDefault, Source::Sources::Default}
};

std::map<IpmiValue, Mode::Modes> modeIpmiToDbus =
{
    {0x03, Mode::Modes::Safe},
    {0x06, Mode::Modes::Setup},
    {ipmiDefault, Mode::Modes::Regular}
};

std::map<Source::Sources, IpmiValue> sourceDbusToIpmi =
{
    {Source::Sources::Network, 0x01},
    {Source::Sources::Disk, 0x02},
    {Source::Sources::ExternalMedia, 0x05},
    {Source::Sources::Default, ipmiDefault}
};

std::map<Mode::Modes, IpmiValue> modeDbusToIpmi =
{
    {Mode::Modes::Safe, 0x03},
    {Mode::Modes::Setup, 0x06},
    {Mode::Modes::Regular, ipmiDefault}
};

} // namespace boot_options

ipmi_ret_t ipmi_chassis_get_sys_boot_options(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                             ipmi_request_t request,
                                             ipmi_response_t response,
                                             ipmi_data_len_t data_len,
                                             ipmi_context_t context)
{
    using namespace boot_options;
    ipmi_ret_t rc = IPMI_CC_PARM_NOT_SUPPORTED;
    char *p = NULL;
    get_sys_boot_options_response_t *resp = (get_sys_boot_options_response_t *) response;
    get_sys_boot_options_t *reqptr = (get_sys_boot_options_t*) request;
    IpmiValue bootOption = ipmiDefault;

    printf("IPMI GET_SYS_BOOT_OPTIONS\n");

    memset(resp,0,sizeof(*resp));
    resp->version   = SET_PARM_VERSION;
    resp->parm      = 5;
    resp->data[0]   = SET_PARM_BOOT_FLAGS_VALID_ONE_TIME;


    /*
     * Parameter #5 means boot flags. Please refer to 28.13 of ipmi doc.
     * This is the only parameter used by petitboot.
     */
    if ( reqptr->parameter == static_cast<uint8_t>
    ( BootOptionParameter::BOOT_FLAGS )) {

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
            auto method =
                dbus.new_method_call(
                     objects.service(bootSourceSetting, bootSourceIntf).c_str(),
                     bootSourceSetting.c_str(),
                     ipmi::PROP_INTF,
                     "Get");
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
            auto bootSource =
                Source::convertSourcesFromString(result.get<std::string>());

            bootSetting = settings::boot::setting(objects, bootModeIntf);
            const auto& bootModeSetting = std::get<settings::Path>(bootSetting);
            method = dbus.new_method_call(
                          objects.service(bootModeSetting, bootModeIntf).
                              c_str(),
                          bootModeSetting.c_str(),
                          ipmi::PROP_INTF,
                          "Get");
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
            auto bootMode =
                Mode::convertModesFromString(result.get<std::string>());

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

            resp->data[0] = oneTimeEnabled ?
                SET_PARM_BOOT_FLAGS_VALID_ONE_TIME:
                SET_PARM_BOOT_FLAGS_VALID_PERMANENT;

            rc = IPMI_CC_OK;
        }
        catch (InternalFailure& e)
        {
            report<InternalFailure>();
            *data_len = 0;
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
    } else if ( reqptr->parameter == static_cast<uint8_t>
    ( BootOptionParameter::OPAL_NETWORK_SETTINGS )) {

        *data_len = static_cast<uint8_t>(BootOptionResponseSize::OPAL_NETWORK_SETTINGS);

        resp->parm = static_cast<uint8_t>(BootOptionParameter::OPAL_NETWORK_SETTINGS);

        int ret = getHostNetworkData(resp);

        if (ret < 0) {

            fprintf(stderr, "getHostNetworkData failed for get_sys_boot_options.\n");
            rc = IPMI_CC_UNSPECIFIED_ERROR;

        }else
            rc = IPMI_CC_OK;
    }

    else {
        fprintf(stderr, "Unsupported parameter 0x%x\n", reqptr->parameter);
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
    set_sys_boot_options_t *reqptr = (set_sys_boot_options_t *) request;

    printf("IPMI SET_SYS_BOOT_OPTIONS reqptr->parameter =[%d]\n",reqptr->parameter);

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

            auto bootSetting =
                settings::boot::setting(objects, bootSourceIntf);

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

                ipmi::setDbusProperty(dbus,
                                      service,
                                      oneTimePath,
                                      enabledIntf,
                                      "Enabled",
                                      !permanent);
            }

            auto modeItr = modeIpmiToDbus.find(bootOption);
            auto sourceItr = sourceIpmiToDbus.find(bootOption);
            if (sourceIpmiToDbus.end() != sourceItr)
            {
                sdbusplus::message::variant<std::string> property =
                    convertForMessage(sourceItr->second);
                auto bootSetting = settings::boot::setting(objects,
                                                           bootSourceIntf);
                const auto& bootSourceSetting =
                    std::get<settings::Path>(bootSetting);
                auto method =
                    dbus.new_method_call(
                         objects.service(bootSourceSetting, bootSourceIntf).
                             c_str(),
                         bootSourceSetting.c_str(),
                         ipmi::PROP_INTF,
                         "Set");
                method.append(bootSourceIntf, "BootSource", property);
                auto reply = dbus.call(method);
                if (reply.is_method_error())
                {
                    log<level::ERR>("Error in BootSource Set");
                    report<InternalFailure>();
                    *data_len = 0;
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }

            }
            if (modeIpmiToDbus.end() != modeItr)
            {
                sdbusplus::message::variant<std::string> property =
                    convertForMessage(modeItr->second);
                auto bootSetting = settings::boot::setting(objects,
                                                           bootModeIntf);
                const auto& bootModeSetting =
                    std::get<settings::Path>(bootSetting);
                auto method =
                    dbus.new_method_call(
                         objects.service(bootModeSetting, bootModeIntf).c_str(),
                         bootModeSetting.c_str(),
                         ipmi::PROP_INTF,
                         "Set");
                method.append(bootModeIntf, "BootMode", property);
                auto reply = dbus.call(method);
                if (reply.is_method_error())
                {
                    log<level::ERR>("Error in BootMode Set");
                    report<InternalFailure>();
                    *data_len = 0;
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
            }
        }
        catch (InternalFailure& e)
        {
            report<InternalFailure>();
            *data_len = 0;
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
    } else if (reqptr->parameter ==
            (uint8_t)BootOptionParameter::OPAL_NETWORK_SETTINGS) {

        int ret = setHostNetworkData(reqptr);
        if (ret < 0) {
            fprintf(stderr, "setHostNetworkData failed for set_sys_boot_options.\n");
            rc = IPMI_CC_UNSPECIFIED_ERROR;
        }
    } else if (reqptr->parameter ==
             static_cast<uint8_t>(BootOptionParameter::BOOT_INFO)) {
        // Handle parameter #4 and return command completed normally
        // (IPMI_CC_OK). There is no implementation in OpenBMC for this
        // parameter. This is added to support the ipmitool command `chassis
        // bootdev` which sends set on parameter #4, before setting the boot
        // flags.
        rc = IPMI_CC_OK;
    } else {
        fprintf(stderr, "Unsupported parameter 0x%x\n", reqptr->parameter);
        rc = IPMI_CC_PARM_NOT_SUPPORTED;
    }

    return rc;
}

void register_netfn_chassis_functions()
{
    // <Wildcard Command>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_CHASSIS, IPMI_CMD_WILDCARD);
    ipmi_register_callback(NETFUN_CHASSIS, IPMI_CMD_WILDCARD, NULL, ipmi_chassis_wildcard,
                           PRIVILEGE_USER);

    // Get Chassis Capabilities
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_CHASSIS, IPMI_CMD_GET_CHASSIS_CAP);
    ipmi_register_callback(NETFUN_CHASSIS, IPMI_CMD_GET_CHASSIS_CAP, NULL, ipmi_get_chassis_cap,
                           PRIVILEGE_USER);

    // <Get System Boot Options>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_CHASSIS, IPMI_CMD_GET_SYS_BOOT_OPTIONS);
    ipmi_register_callback(NETFUN_CHASSIS, IPMI_CMD_GET_SYS_BOOT_OPTIONS, NULL,
                           ipmi_chassis_get_sys_boot_options, PRIVILEGE_OPERATOR);

    // <Get Chassis Status>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_CHASSIS, IPMI_CMD_CHASSIS_STATUS);
    ipmi_register_callback(NETFUN_CHASSIS, IPMI_CMD_CHASSIS_STATUS, NULL, ipmi_get_chassis_status,
                           PRIVILEGE_USER);

    // <Chassis Control>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_CHASSIS, IPMI_CMD_CHASSIS_CONTROL);
    ipmi_register_callback(NETFUN_CHASSIS, IPMI_CMD_CHASSIS_CONTROL, NULL, ipmi_chassis_control,
                           PRIVILEGE_OPERATOR);

    // <Chassis Identify>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_CHASSIS, IPMI_CMD_CHASSIS_IDENTIFY);
    ipmi_register_callback(NETFUN_CHASSIS, IPMI_CMD_CHASSIS_IDENTIFY, NULL,
                           ipmi_chassis_identify, PRIVILEGE_OPERATOR);

    // <Set System Boot Options>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n", NETFUN_CHASSIS, IPMI_CMD_SET_SYS_BOOT_OPTIONS);
    ipmi_register_callback(NETFUN_CHASSIS, IPMI_CMD_SET_SYS_BOOT_OPTIONS, NULL,
                           ipmi_chassis_set_sys_boot_options, PRIVILEGE_OPERATOR);
}
