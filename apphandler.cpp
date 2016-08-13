#include "apphandler.h"
#include "ipmid-api.h"
#include "ipmid.hpp"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <systemd/sd-bus.h>
#include <mapper.h>
#include <array>

extern sd_bus *bus;

void register_netfn_app_functions() __attribute__((constructor));

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

//---------------------------------------------------------------------
// Called by Host on seeing a SMS_ATN bit set. Return a hardcoded
// value of 0x2 indicating we need Host read some data.
//-------------------------------------------------------------------
ipmi_ret_t ipmi_app_get_msg_flags(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
	// Generic return from IPMI commands.
    ipmi_ret_t rc = IPMI_CC_OK;

    printf("IPMI APP GET MSG FLAGS returning with [bit:2] set\n");

	// From IPMI spec V2.0 for Get Message Flags Command :
	// bit:[1] from LSB : 1b = Event Message Buffer Full.
	// Return as 0 if Event Message Buffer is not supported,
	// or when the Event Message buffer is disabled.
	// TODO. For now. assume its not disabled and send "0x2" anyway:

	uint8_t set_event_msg_buffer_full = 0x2;
    *data_len = sizeof(set_event_msg_buffer_full);

    // Pack the actual response
    memcpy(response, &set_event_msg_buffer_full, *data_len);

    return rc;
}

//-------------------------------------------------------------------
// Called by Host post response from Get_Message_Flags
//-------------------------------------------------------------------
ipmi_ret_t ipmi_app_read_event(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    printf("IPMI APP READ EVENT command received\n");

	// TODO : For now, this is catering only to the Soft Power Off via OEM SEL
	//        mechanism. If we need to make this generically used for some
	//        other conditions, then we can take advantage of context pointer.

	struct oem_sel_timestamped soft_off = {0};
    *data_len = sizeof(struct oem_sel_timestamped);

	// either id[0] -or- id[1] can be filled in. We will use id[0]
	soft_off.id[0]	 = SEL_OEM_ID_0;
	soft_off.id[1]	 = SEL_OEM_ID_0;
	soft_off.type	 = SEL_RECORD_TYPE_OEM;

	// Following 3 bytes are from IANA Manufactre_Id field. See below
	soft_off.manuf_id[0]= 0x41;
	soft_off.manuf_id[1]= 0xA7;
	soft_off.manuf_id[2]= 0x00;

	// per IPMI spec NetFuntion for OEM
	soft_off.netfun	 = 0x3A;

	// Mechanism to kick start soft shutdown.
	soft_off.cmd	 = CMD_POWER;
	soft_off.data[0] = SOFT_OFF;

	// All '0xFF' since unused.
	memset(&soft_off.data[1], 0xFF, 3);

    // Pack the actual response
    memcpy(response, &soft_off, *data_len);
    return rc;
}

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
    char hexbyte[5];
    int l;
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
        fprintf(stderr, "Failed to get bus name, return value: %s.\n", strerror(-r));
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
        fprintf(stderr, "Failed to get bus name, return value: %s.\n", strerror(-r));
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

    uint8_t str[] = {0x01, MAX_IPMI_BUFFER, MAX_IPMI_BUFFER, 0x0A, 0x01};

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
    const char  *objname = "/org/openbmc/watchdog/host0";
    const char  *iface = "org.openbmc.Watchdog";
    sd_bus_message *reply = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int r = 0;

    set_wd_data_t *reqptr = (set_wd_data_t*) request;
    uint16_t timer = 0;
    uint32_t timer_ms = 0;
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
        fprintf(stderr, "Failed to get bus name, return value: %s.\n", strerror(-r));
        goto finish;
    }
    // Set watchdog timer
    r = sd_bus_call_method(bus, busname, objname, iface,
                           "set", &error, &reply, "i", timer_ms);
    if(r < 0)
    {
        fprintf(stderr, "Failed to call the SET method: %s\n", strerror(-r));
        goto finish;
    }

    sd_bus_error_free(&error);
    reply = sd_bus_message_unref(reply);

    // Stop the current watchdog if any
    r = sd_bus_call_method(bus, busname, objname, iface,
                           "stop", &error, &reply, NULL);
    if(r < 0)
    {
        fprintf(stderr, "Failed to call the STOP method: %s\n", strerror(-r));
        goto finish;
    }

    if (reqptr->t_use & 0x40)
    {
        sd_bus_error_free(&error);
        reply = sd_bus_message_unref(reply);

        // Start the watchdog if requested
        r = sd_bus_call_method(bus, busname, objname, iface,
                               "start", &error, &reply, NULL);
        if(r < 0)
        {
            fprintf(stderr, "Failed to call the START method: %s\n", strerror(-r));
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
    const char  *objname = "/org/openbmc/watchdog/host0";
    const char  *iface = "org.openbmc.Watchdog";
    sd_bus_message *reply = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int r = 0;
    char *busname = NULL;

    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;

    printf("WATCHDOG RESET\n");
    // Get bus name
    r = mapper_get_service(bus, objname, &busname);
    if (r < 0) {
        fprintf(stderr, "Failed to get bus name, return value: %s.\n", strerror(-r));
        goto finish;
    }
    // Refresh watchdog
    r = sd_bus_call_method(bus, busname, objname, iface,
                           "poke", &error, &reply, NULL);
    if (r < 0) {
        fprintf(stderr, "Failed to add reset  watchdog: %s\n", strerror(-r));
        rc = -1;
    }

finish:
    sd_bus_error_free(&error);
    reply = sd_bus_message_unref(reply);
    free(busname);

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

ipmi_ret_t ipmi_app_set_bmc_global_enables(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;

    // Event and message logging enabled by default so return for now
    printf("IPMI APP SET BMC GLOBAL ENABLES Ignoring for now\n");

    return rc;
}



ipmi_ret_t ipmi_app_wildcard_handler(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    printf("Handling WILDCARD Netfn:[0x%X], Cmd:[0x%X]\n",netfn, cmd);

    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;

    *data_len = strlen("THIS IS WILDCARD");

    // Now pack actual response
    memcpy(response, "THIS IS WILDCARD", *data_len);

    return rc;
}

void register_netfn_app_functions()
{
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_GET_CAP_BIT);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_CAP_BIT, NULL, ipmi_app_get_bt_capabilities);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_WILDCARD);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_WILDCARD, NULL, ipmi_app_wildcard_handler);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_RESET_WD);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_RESET_WD, NULL, ipmi_app_reset_watchdog);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_SET_WD);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_SET_WD, NULL, ipmi_app_set_watchdog);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_GET_DEVICE_ID);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_DEVICE_ID, NULL, ipmi_app_get_device_id);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_GET_DEVICE_GUID);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_DEVICE_GUID, NULL, ipmi_app_get_device_guid);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_SET_ACPI);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_SET_ACPI, NULL, ipmi_app_set_acpi_power_state);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_READ_EVENT);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_READ_EVENT, NULL, ipmi_app_read_event);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP,
                                            IPMI_CMD_SET_BMC_GLOBAL_ENABLES);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_SET_BMC_GLOBAL_ENABLES, NULL,
                                            ipmi_app_set_bmc_global_enables);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_GET_MSG_FLAGS);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_MSG_FLAGS, NULL, ipmi_app_get_msg_flags);


    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_GET_CHAN_INFO);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_CHAN_INFO, NULL, ipmi_app_channel_info);



    return;
}


