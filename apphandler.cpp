#include "apphandler.h"
#include "app/channel.hpp"
#include "app/watchdog.hpp"
#include "host-ipmid/ipmid-api.h"
#include "ipmid.hpp"
#include "types.hpp"
#include "utils.hpp"

#include <stdio.h>
#include <stdint.h>
#include <systemd/sd-bus.h>
#include <mapper.h>
#include <array>
#include <vector>
#include <string>
#include <cstddef>
#include <experimental/filesystem>

#include <arpa/inet.h>
#include "transporthandler.hpp"

#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include "xyz/openbmc_project/Common/error.hpp"

extern sd_bus *bus;

constexpr auto app_obj = "/org/openbmc/NetworkManager/Interface";
constexpr auto app_ifc = "org.openbmc.NetworkManager";
constexpr auto app_nwinterface = "eth0";

void register_netfn_app_functions() __attribute__((constructor));

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
namespace fs = std::experimental::filesystem;

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

/* Currently supports the vx.x-x-[-x] and v1.x.x-x-[-x] format. It will     */
/* return -1 if not in those formats, this routine knows how to parse       */
/* version = v0.6-19-gf363f61-dirty                                         */
/*            ^ ^ ^^          ^                                             */
/*            | |  |----------|-- additional details                        */
/*            | |---------------- Minor                                     */
/*            |------------------ Major                                     */
/* and version = v1.99.10-113-g65edf7d-r3-0-g9e4f715                        */
/*                ^ ^  ^^ ^                                                 */
/*                | |  |--|---------- additional details                    */
/*                | |---------------- Minor                                 */
/*                |------------------ Major                                 */
/* Additional details : If the option group exists it will force Auxiliary  */
/* Firmware Revision Information 4th byte to 1 indicating the build was     */
/* derived with additional edits                                            */
int convert_version(const char * p, rev_t *rev)
{
    std::string s(p);
    std::string token;
    uint16_t commits;

    auto location  = s.find_first_of('v');
    if (location != std::string::npos)
    {
        s = s.substr(location+1);
    }

    if (!s.empty())
    {
        location = s.find_first_of(".-");
        if (location != std::string::npos)
        {
            rev->major = static_cast<char>(std::stoi(s.substr(0, location), 0, 16));
            token = s.substr(location+1);
        }

        if (!token.empty())
        {
            location = token.find_first_of(".-");
            if (location != std::string::npos)
            {
                rev->minor = static_cast<char>(std::stoi(token.substr(0, location), 0, 16));
                token = token.substr(location+1);
            }
        }

        // Capture the number of commits on top of the minor tag.
        // I'm using BE format like the ipmi spec asked for
        location = token.find_first_of(".-");
        if (!token.empty())
        {
            commits = std::stoi(token.substr(0, location), 0, 16);
            rev->d[0] = (commits>>8) | (commits<<8);

            // commit number we skip
            location = token.find_first_of(".-");
            if (location != std::string::npos)
            {
                token = token.substr(location+1);
            }
        }
        else {
            rev->d[0] = 0;
        }

        if (location != std::string::npos)
        {
            token = token.substr(location+1);
        }

        // Any value of the optional parameter forces it to 1
        location = token.find_first_of(".-");
        if (location != std::string::npos)
        {
            token = token.substr(location+1);
        }
        commits = (!token.empty()) ? 1 : 0;

        //We do this operation to get this displayed in least significant bytes
        //of ipmitool device id command.
        rev->d[1] = (commits>>8) | (commits<<8);
    }

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

    // IPMI Spec version 2.0
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
    //  56h - Self Test function not implemented in this controller.
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

    // <Get Channel Access>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_GET_CHANNEL_ACCESS);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_CHANNEL_ACCESS, NULL,
                           ipmi_get_channel_access, PRIVILEGE_USER);

    // <Get Channel Info Command>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_GET_CHAN_INFO);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_CHAN_INFO, NULL, ipmi_app_channel_info,
                           PRIVILEGE_USER);

    return;
}


