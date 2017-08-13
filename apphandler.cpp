#include "apphandler.h"
#include "host-ipmid/ipmid-api.h"
#include "ipmid.hpp"
#include "types.hpp"
#include "utils.hpp"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <systemd/sd-bus.h>
#include <mapper.h>
#include <array>
#include <arpa/inet.h>
#include "transporthandler.hpp"

#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include "xyz/openbmc_project/Common/error.hpp"

extern sd_bus *bus;

constexpr auto app_obj = "/org/openbmc/NetworkManager/Interface";
constexpr auto app_ifc = "org.openbmc.NetworkManager";
constexpr auto app_nwinterface = "eth0";

constexpr auto ipv4Protocol = "xyz.openbmc_project.Network.IP.Protocol.IPv4";

void register_netfn_app_functions() __attribute__((constructor));

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

// Offset in get device id command.
typedef struct
{
   uint8_t id;
   uint8_t revision;
   uint8_t fw[2];
   uint8_t ipmi_ver;
   uint8_t addn_dev_support;
   uint8_t manuf_id[3];
   uint8_t prod_id[2];
   uint8_t aux[4];
}__attribute__((packed)) ipmi_device_id_t;

ipmi_ret_t ipmi_app_set_acpi_power_state(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;

    printf("IPMI SET ACPI STATE Ignoring for now\n");
    return rc;
}


typedef struct
{
    char major;
    char minor;
    uint16_t d[2];
} rev_t;


/* Currently only supports the vx.x-x-[-x] format Will return -1 if not in  */
/* the format this routine knows how to parse                               */
/* version = v0.6-19-gf363f61-dirty                                         */
/*            ^ ^ ^^          ^                                             */
/*            | |  |----------|-- additional details                        */
/*            | |---------------- Minor                                     */
/*            |------------------ Major                                     */
/* Additional details : If the option group exists it will force Auxiliary  */
/* Firmware Revision Information 4th byte to 1 indicating the build was     */
/* derived with additional edits                                            */
int convert_version(const char *p, rev_t *rev)
{
    char *s, *token;
    uint16_t commits;

    if (*p != 'v')
        return -1;
    p++;

    s = strdup(p);
    token = strtok(s,".-");

    rev->major = (int8_t) atoi(token);

    token = strtok(NULL, ".-");
    rev->minor = (int8_t) atoi(token);

    // Capture the number of commits on top of the minor tag.
    // I'm using BE format like the ipmi spec asked for
    token = strtok(NULL,".-");

    if (token) {
        commits = (int16_t) atoi(token);
        rev->d[0] = (commits>>8) | (commits<<8);

        // commit number we skip
        token = strtok(NULL,".-");

    } else {
        rev->d[0] = 0;
    }

    // Any value of the optional parameter forces it to 1
    if (token)
        token = strtok(NULL,".-");

    rev->d[1] = (token != NULL) ? 1 : 0;

    free(s);
    return 0;
}

ipmi_ret_t ipmi_app_get_device_id(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    const char  *objname = "/org/openbmc/inventory/system/chassis/motherboard/bmc";
    const char  *iface   = "org.openbmc.InventoryItem";
    char *ver = NULL;
    char *busname = NULL;
    int r;
    rev_t rev = {0};
    ipmi_device_id_t dev_id{};

    // Data length
    *data_len = sizeof(dev_id);

    // From IPMI spec, controller that have different application commands, or different
    // definitions of OEM fields, are expected to have different Device ID values.
    // Set to 0 now.

    // Device Revision is set to 0 now.
    // Bit7 identifies if device provide Device SDRs,  obmc don't have SDR,we use ipmi to
    // simulate SDR, hence the value:
    dev_id.revision = 0x80;

    // Firmware revision is already implemented, so get it from appropriate position.
    r = mapper_get_service(bus, objname, &busname);
    if (r < 0) {
        fprintf(stderr, "Failed to get %s bus name: %s\n",
                objname, strerror(-r));
        goto finish;
    }
    r = sd_bus_get_property_string(bus,busname,objname,iface,"version", NULL, &ver);
    if ( r < 0 ) {
        fprintf(stderr, "Failed to obtain version property: %s\n", strerror(-r));
    } else {
        r = convert_version(ver, &rev);
        if( r >= 0 ) {
            // bit7 identifies if the device is available, 0=normal operation,
            // 1=device firmware, SDR update or self-initialization in progress.
            // our SDR is normal working condition, so mask:
            dev_id.fw[0] = 0x7F & rev.major;

            rev.minor = (rev.minor > 99 ? 99 : rev.minor);
            dev_id.fw[1] = rev.minor % 10 + (rev.minor / 10) * 16;
            memcpy(&dev_id.aux, rev.d, 4);
        }
    }

    // IPMI Spec verison 2.0
    dev_id.ipmi_ver = 2;

    // Additional device Support.
    // List the 'logical device' commands and functions that the controller supports
    // that are in addition to the mandatory IPM and Application commands.
    // [7] Chassis Device (device functions as chassis device per ICMB spec.)
    // [6] Bridge (device responds to Bridge NetFn commands)
    // [5] IPMB Event Generator
    // [4] IPMB Event Receiver
    // [3] FRU Inventory Device
    // [2] SEL Device
    // [1] SDR Repository Device
    // [0] Sensor Device
    // We support FRU/SEL/Sensor now:
    dev_id.addn_dev_support = 0x8D;

    // This value is the IANA number assigned to "IBM Platform Firmware
    // Division", which is also used by our service processor.  We may want
    // a different number or at least a different version?
    dev_id.manuf_id[0] = 0x41;
    dev_id.manuf_id[1] = 0xA7;
    dev_id.manuf_id[2] = 0x00;

    // Witherspoon's product ID is hardcoded to 4F42(ASCII 'OB').
    // TODO: openbmc/openbmc#495
    dev_id.prod_id[0] = 0x4F;
    dev_id.prod_id[1] = 0x42;

    // Pack the actual response
    memcpy(response, &dev_id, *data_len);
finish:
    free(busname);
    free(ver);
    return rc;
}

ipmi_ret_t ipmi_app_get_self_test_results(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;

    // Byte 2:
    //  55h - No error.
    //  56h - Self Test funciton not implemented in this controller.
    //  57h - Corrupted or inaccesssible data or devices.
    //  58h - Fatal hardware error.
    //  FFh - reserved.
    //  all other: Device-specific 'internal failure'.
    //  Byte 3:
    //      For byte 2 = 55h, 56h, FFh:     00h
    //      For byte 2 = 58h, all other:    Device-specific
    //      For byte 2 = 57h:   self-test error bitfield.
    //      Note: returning 57h does not imply that all test were run.
    //      [7] 1b = Cannot access SEL device.
    //      [6] 1b = Cannot access SDR Repository.
    //      [5] 1b = Cannot access BMC FRU device.
    //      [4] 1b = IPMB signal lines do not respond.
    //      [3] 1b = SDR Repository empty.
    //      [2] 1b = Internal Use Area of BMC FRU corrupted.
    //      [1] 1b = controller update 'boot block' firmware corrupted.
    //      [0] 1b = controller operational firmware corrupted.

    char selftestresults[2] = {0};

    *data_len = 2;

    selftestresults[0] = 0x56;
    selftestresults[1] = 0;

    memcpy(response, selftestresults, *data_len);

    return rc;
}

ipmi_ret_t ipmi_app_get_device_guid(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    const char  *objname = "/org/openbmc/control/chassis0";
    const char  *iface = "org.freedesktop.DBus.Properties";
    const char  *chassis_iface = "org.openbmc.control.Chassis";
    sd_bus_message *reply = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int r = 0;
    char *uuid = NULL;
    char *busname = NULL;

    // UUID is in RFC4122 format. Ex: 61a39523-78f2-11e5-9862-e6402cfc3223
    // Per IPMI Spec 2.0 need to convert to 16 hex bytes and reverse the byte order
    // Ex: 0x2332fc2c40e66298e511f2782395a361

    const int resp_size = 16; // Response is 16 hex bytes per IPMI Spec
    uint8_t resp_uuid[resp_size]; // Array to hold the formatted response
    int resp_loc = resp_size-1; // Point resp end of array to save in reverse order
    int i = 0;
    char *tokptr = NULL;
    char *id_octet = NULL;

    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;

    printf("IPMI GET DEVICE GUID\n");

    // Call Get properties method with the interface and property name
    r = mapper_get_service(bus, objname, &busname);
    if (r < 0) {
        fprintf(stderr, "Failed to get %s bus name: %s\n",
                objname, strerror(-r));
        goto finish;
    }
    r = sd_bus_call_method(bus,busname,objname,iface,
                           "Get",&error, &reply, "ss",
                           chassis_iface, "uuid");
    if (r < 0)
    {
        fprintf(stderr, "Failed to call Get Method: %s\n", strerror(-r));
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        goto finish;
    }

    r = sd_bus_message_read(reply, "v", "s", &uuid);
    if (r < 0 || uuid == NULL)
    {
        fprintf(stderr, "Failed to get a response: %s", strerror(-r));
        rc = IPMI_CC_RESPONSE_ERROR;
        goto finish;
    }

    // Traverse the UUID
    id_octet = strtok_r(uuid, "-", &tokptr); // Get the UUID octects separated by dash

    if (id_octet == NULL)
    {
        // Error
        fprintf(stderr, "Unexpected UUID format: %s", uuid);
        rc = IPMI_CC_RESPONSE_ERROR;
        goto finish;
    }

    while (id_octet != NULL)
    {
        // Calculate the octet string size since it varies
        // Divide it by 2 for the array size since 1 byte is built from 2 chars
        int tmp_size = strlen(id_octet)/2;

        for(i = 0; i < tmp_size; i++)
        {
            char tmp_array[3] = {0}; // Holder of the 2 chars that will become a byte
            strncpy(tmp_array, id_octet, 2); // 2 chars at a time

            int resp_byte = strtoul(tmp_array, NULL, 16); // Convert to hex byte
            memcpy((void*)&resp_uuid[resp_loc], &resp_byte, 1); // Copy end to first
            resp_loc--;
            id_octet+=2; // Finished with the 2 chars, advance
        }
        id_octet=strtok_r(NULL, "-", &tokptr); // Get next octet
    }

    // Data length
    *data_len = resp_size;

    // Pack the actual response
    memcpy(response, &resp_uuid, *data_len);

finish:
    sd_bus_error_free(&error);
    reply = sd_bus_message_unref(reply);
    free(busname);

    return rc;
}

ipmi_ret_t ipmi_app_get_bt_capabilities(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    printf("Handling Netfn:[0x%X], Cmd:[0x%X]\n",netfn,cmd);

    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;

    // Per IPMI 2.0 spec, the input and output buffer size must be the max
    // buffer size minus one byte to allocate space for the length byte.
    uint8_t str[] = {0x01, MAX_IPMI_BUFFER-1, MAX_IPMI_BUFFER-1, 0x0A, 0x01};

    // Data length
    *data_len = sizeof(str);

    // Pack the actual response
    memcpy(response, &str, *data_len);

    return rc;
}


struct set_wd_data_t {
    uint8_t t_use;
    uint8_t t_action;
    uint8_t preset;
    uint8_t flags;
    uint8_t ls;
    uint8_t ms;
}  __attribute__ ((packed));



ipmi_ret_t ipmi_app_set_watchdog(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    const char  *objname = "/xyz/openbmc_project/watchdog/host0";
    const char  *iface = "xyz.openbmc_project.State.Watchdog";
    const char  *property_iface = "org.freedesktop.DBus.Properties";
    sd_bus_message *reply = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int r = 0;

    set_wd_data_t *reqptr = (set_wd_data_t*) request;
    uint16_t timer = 0;

    // Making this uint64_t to match with provider
    uint64_t timer_ms = 0;
    char *busname = NULL;
    *data_len = 0;

    // Get number of 100ms intervals
    timer = (((uint16_t)reqptr->ms) << 8) + reqptr->ls;
    // Get timer value in ms
    timer_ms = timer * 100;

    printf("WATCHDOG SET Timer:[0x%X] 100ms intervals\n",timer);

    // Get bus name
    r = mapper_get_service(bus, objname, &busname);
    if (r < 0) {
        fprintf(stderr, "Failed to get %s bus name: %s\n",
                objname, strerror(-r));
        goto finish;
    }

    // Disable watchdog if running
    r = sd_bus_call_method(bus, busname, objname, property_iface,
                           "Set", &error, &reply, "ssv",
                           iface, "Enabled", "b", false);
    if(r < 0) {
        fprintf(stderr, "Failed to disable Watchdog: %s\n",
                    strerror(-r));
        goto finish;
    }

    if (reqptr->t_use & 0x40)
    {
        sd_bus_error_free(&error);
        reply = sd_bus_message_unref(reply);

        // Now Enable Watchdog
        r = sd_bus_call_method(bus, busname, objname, property_iface,
                               "Set", &error, &reply, "ssv",
                               iface, "Enabled", "b", true);
        if(r < 0) {
            fprintf(stderr, "Failed to Enable Watchdog: %s\n",
                    strerror(-r));
            goto finish;
        }

        // Set watchdog timer
        r = sd_bus_call_method(bus, busname, objname, property_iface,
                               "Set", &error, &reply, "ssv",
                               iface, "TimeRemaining", "t", timer_ms);
        if(r < 0) {
            fprintf(stderr, "Failed to set new expiration time: %s\n",
                    strerror(-r));
            goto finish;
        }
    }

finish:
    sd_bus_error_free(&error);
    reply = sd_bus_message_unref(reply);
    free(busname);

    return (r < 0) ? -1 : IPMI_CC_OK;
}


ipmi_ret_t ipmi_app_reset_watchdog(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    const char  *objname = "/xyz/openbmc_project/watchdog/host0";
    const char  *iface = "xyz.openbmc_project.State.Watchdog";
    const char  *property_iface = "org.freedesktop.DBus.Properties";
    sd_bus_message *reply = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int r = 0;
    char *busname = NULL;

    // Current time interval that is set in watchdog.
    uint64_t interval = 0;

    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;

    printf("WATCHDOG RESET\n");
    // Get bus name
    r = mapper_get_service(bus, objname, &busname);
    if (r < 0) {
        fprintf(stderr, "Failed to get %s bus name: %s\n",
                objname, strerror(-r));
        goto finish;
    }

    // Get the current interval and set it back.
    r = sd_bus_call_method(bus, busname, objname, property_iface,
                           "Get", &error, &reply, "ss",
                           iface, "Interval");

    if(r < 0) {
        fprintf(stderr, "Failed to get current Interval msg: %s\n",
                strerror(-r));
        goto finish;
    }

    // Now extract the value
    r = sd_bus_message_read(reply, "v", "t", &interval);
    if (r < 0) {
        fprintf(stderr, "Failed to read current interval: %s\n",
                strerror(-r));
        goto finish;
    }

    sd_bus_error_free(&error);
    reply = sd_bus_message_unref(reply);

    // Set watchdog timer
    r = sd_bus_call_method(bus, busname, objname, property_iface,
                           "Set", &error, &reply, "ssv",
                           iface, "TimeRemaining", "t", interval);
    if(r < 0) {
        fprintf(stderr, "Failed to refresh the timer: %s\n",
                strerror(-r));
        goto finish;
    }

finish:
    sd_bus_error_free(&error);
    reply = sd_bus_message_unref(reply);
    free(busname);

    return rc;
}

extern struct ChannelConfig_t channelConfig;

ipmi_ret_t ipmi_set_channel_access(ipmi_netfn_t netfn,
                                   ipmi_cmd_t cmd,
                                   ipmi_request_t request,
                                   ipmi_response_t response,
                                   ipmi_data_len_t data_len,
                                   ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;

    std::string ipaddress;
    std::string gateway;
    uint8_t prefix {};
    uint32_t vlanID {};

    // Todo: parse the request data if needed.

    // Using Set Channel cmd to apply changes of Set Lan Cmd.
    try
    {

        sdbusplus::bus::bus bus(ipmid_get_sd_bus_connection());

        log<level::INFO>("Network data from Cache",
                         entry("PREFIX=%s", channelConfig.netmask.c_str()),
                         entry("ADDRESS=%s", channelConfig.ipaddr.c_str()),
                         entry("GATEWAY=%s", channelConfig.gateway.c_str()));

        auto systemObject = ipmi::getDbusObject(bus,
                                 ipmi::network::SYSTEMCONFIG_INTERFACE,
                                 ipmi::network::ROOT);

        // TODO Currently IPMI supports single interface,need to handle
        // Multiple interface through
        // https://github.com/openbmc/openbmc/issues/2138

        auto networkInterfaceObject = ipmi::getDbusObject(
                    bus,
                    ipmi::network::ETHERNET_INTERFACE,
                    ipmi::network::ROOT,
                    ipmi::network::INTERFACE);



        // check wthether user has given all the data
        if (!channelConfig.ipaddr.empty() &&
            !channelConfig.netmask.empty() &&
            !channelConfig.gateway.empty())
        {
            //convert mask into prefix
            ipaddress = channelConfig.ipaddr;
            prefix = ipmi::network::toPrefix(AF_INET, channelConfig.netmask);
            gateway = channelConfig.gateway;

            if (channelConfig.vlanID != ipmi::network::VLAN_ID_MASK)
            {
                //get the first twelve bits which is vlan id
                //not interested in rest of the bits.
                vlanID = channelConfig.vlanID & ipmi::network::VLAN_ID_MASK;
                channelConfig.vlanID = le32toh(channelConfig.vlanID);
            }

        }
        else
        {
            // We have partial filled cache so get the remaning
            // info from the system.

            // gets the network data from the system as user has
            // not given all the data then use the data fetched from the
            // system but it is implementation dependent,IPMI spec doesn't
            // force it.

            // if system is not having any ip object don't throw error,
            try
            {
                auto ipObjectInfo = ipmi::getDbusObject(bus,
                        ipmi::network::IP_INTERFACE,
                        ipmi::network::ROOT,
                        ipmi::network::IP_TYPE);

                auto properties = ipmi::getAllDbusProperties(bus,
                        ipObjectInfo.second,
                        ipObjectInfo.first,
                        ipmi::network::IP_INTERFACE);

                ipaddress = channelConfig.ipaddr.empty() ?
                    std::move(properties["Address"].get<std::string>()) :
                    channelConfig.ipaddr;

                prefix = channelConfig.netmask.empty() ?
                    properties["PrefixLength"].get<uint8_t>() :
                    ipmi::network::toPrefix(AF_INET,
                                            channelConfig.netmask);

                if (channelConfig.vlanID != ipmi::network::VLAN_ID_MASK)
                {
                    //get the first twelve bits which is vlan id
                    //not interested in rest of the bits.
                    vlanID = channelConfig.vlanID & ipmi::network::VLAN_ID_MASK;
                    channelConfig.vlanID = le32toh(channelConfig.vlanID);
                }
                else
                {
                    vlanID = ipmi::network::getVLAN(ipObjectInfo.first);
                }

            }
            catch (InternalFailure& e)
            {
                log<level::INFO>("Failed to get IP object which matches",
                        entry("INTERFACE=%s", ipmi::network::IP_INTERFACE),
                        entry("MATCH=%s", ipmi::network::IP_TYPE));
            }

            auto systemProperties = ipmi::getAllDbusProperties(
                    bus,
                    systemObject.second,
                    systemObject.first,
                    ipmi::network::SYSTEMCONFIG_INTERFACE);

            gateway = channelConfig.gateway.empty() ?
                std::move(systemProperties["DefaultGateway"].get<std::string>()) :
                channelConfig.gateway;

        }

        // Currently network manager doesn't support purging of all the
        // ip addresses and the vlan interfaces from the parent interface,
        // TODO once the support is there, will make the change here.
        // https://github.com/openbmc/openbmc/issues/2141.

        // TODO Currently IPMI supports single interface,need to handle
        // Multiple interface through
        // https://github.com/openbmc/openbmc/issues/2138

        //delete all the vlan interfaces
        //delete all the ipv4 addresses
        ipmi::deleteAllDbusObjects(bus, ipmi::network::ROOT,
                                   ipmi::network::VLAN_INTERFACE);
        ipmi::deleteAllDbusObjects(bus, ipmi::network::ROOT,
                                   ipmi::network::IP_INTERFACE,
                                   ipmi::network::IP_TYPE);
        if (vlanID)
        {
            ipmi::network::createVLAN(bus, ipmi::network::SERVICE,
                                      ipmi::network::ROOT,
                                      ipmi::network::INTERFACE, vlanID);

            networkInterfaceObject = ipmi::getDbusObject(
                    bus,
                    ipmi::network::VLAN_INTERFACE,
                    ipmi::network::ROOT);
        }

        ipmi::network::createIP(bus, networkInterfaceObject.second,
                                networkInterfaceObject.first,
                                ipv4Protocol, ipaddress, prefix);

        ipmi::setDbusProperty(bus, systemObject.second, systemObject.first,
                              ipmi::network::SYSTEMCONFIG_INTERFACE,
                              "DefaultGateway", gateway);

    }
    catch (InternalFailure& e)
    {
        log<level::ERR>("Failed to set network data",
                        entry("PREFIX=%d", prefix),
                        entry("ADDRESS=%s", ipaddress),
                        entry("GATEWAY=%s", gateway));

        commit<InternalFailure>();
        rc = IPMI_CC_UNSPECIFIED_ERROR;
    }

    channelConfig.clear();
    return rc;
}


// ATTENTION: This ipmi function is very hardcoded on purpose
// OpenBMC does not fully support IPMI.  This command is useful
// to have around because it enables testing of interfaces with
// the IPMI tool.
#define GET_CHANNEL_INFO_CHANNEL_OFFSET 0
// IPMI Table 6-2
#define IPMI_CHANNEL_TYPE_IPMB 1
// IPMI Table 6-3
#define IPMI_CHANNEL_MEDIUM_TYPE_OTHER 6

ipmi_ret_t ipmi_app_channel_info(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    uint8_t resp[] = {
        1,
        IPMI_CHANNEL_MEDIUM_TYPE_OTHER,
        IPMI_CHANNEL_TYPE_IPMB,
        1,0x41,0xA7,0x00,0,0};
    uint8_t *p = (uint8_t*) request;

    printf("IPMI APP GET CHANNEL INFO\n");

    // The supported channels numbers are 1 and 8.
    // Channel Number E is used as way to identify the current channel
    // that the command is being is received from.
    if (*p == 0xe || *p == 1 || *p == 8) {

        *data_len = sizeof(resp);
        memcpy(response, resp, *data_len);

    } else {
        rc = IPMI_CC_PARM_OUT_OF_RANGE;
        *data_len = 0;
    }

    return rc;
}

ipmi_ret_t ipmi_app_wildcard_handler(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    printf("Handling WILDCARD Netfn:[0x%X], Cmd:[0x%X]\n",netfn, cmd);

    // Status code.
    ipmi_ret_t rc = IPMI_CC_INVALID;

    *data_len = strlen("THIS IS WILDCARD");

    // Now pack actual response
    memcpy(response, "THIS IS WILDCARD", *data_len);

    return rc;
}

void register_netfn_app_functions()
{
    // <Get BT Interface Capabilities>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_GET_CAP_BIT);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_CAP_BIT, NULL, ipmi_app_get_bt_capabilities,
                           PRIVILEGE_USER);

    // <Wildcard Command>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_WILDCARD);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_WILDCARD, NULL, ipmi_app_wildcard_handler,
                           PRIVILEGE_USER);

    // <Reset Watchdog Timer>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_RESET_WD);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_RESET_WD, NULL, ipmi_app_reset_watchdog,
                           PRIVILEGE_OPERATOR);

    // <Set Watchdog Timer>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_SET_WD);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_SET_WD, NULL, ipmi_app_set_watchdog,
                           PRIVILEGE_OPERATOR);

    // <Get Device ID>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_GET_DEVICE_ID);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_DEVICE_ID, NULL, ipmi_app_get_device_id,
                           PRIVILEGE_USER);

    // <Get Self Test Results>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_GET_SELF_TEST_RESULTS);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_SELF_TEST_RESULTS, NULL,
                    ipmi_app_get_self_test_results, PRIVILEGE_USER);

    // <Get Device GUID>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_GET_DEVICE_GUID);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_DEVICE_GUID, NULL, ipmi_app_get_device_guid,
                           PRIVILEGE_USER);

    // <Set ACPI Power State>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_SET_ACPI);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_SET_ACPI, NULL, ipmi_app_set_acpi_power_state,
                           PRIVILEGE_ADMIN);

    // <Set Channel Access>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP,
                                            IPMI_CMD_SET_CHAN_ACCESS);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_SET_CHAN_ACCESS, NULL,
                                    ipmi_set_channel_access, PRIVILEGE_ADMIN);

    // <Get Channel Info Command>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_GET_CHAN_INFO);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_CHAN_INFO, NULL, ipmi_app_channel_info,
                           PRIVILEGE_USER);

    return;
}


