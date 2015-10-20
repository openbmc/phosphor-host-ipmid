#include "apphandler.h"
#include "ipmid-api.h"
#include "ipmid.H"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <systemd/sd-bus.h>

extern sd_bus *bus;

void register_netfn_app_functions() __attribute__((constructor));


ipmi_ret_t ipmi_app_read_event(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;

    printf("IPMI APP READ EVENT Ignoring for now\n");
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

ipmi_ret_t ipmi_app_get_device_id(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;

    // TODO GET REAL VALUES HERE....  I made these ones up because
    // we are in bringup mode.  Version Major and Minor can be what we
    // want like v1.03  but the IANA really should be something that
    // we own.  I would suggest getting the IANA from Hostboot as
    // long as IBM owns it then no problem.  If some other company
    // gave us the IANA to use then use the one we have from the
    // FSP ipmi code.
    uint8_t str[] = {0x00, 0, 1, 1,2, 0xD, 0x41, 0xA7, 0x00, 0x43, 0x40};

    // Data length
    *data_len = sizeof(str);

    // Pack the actual response
    memcpy(response, &str, *data_len);
    return rc;
}

ipmi_ret_t ipmi_app_get_device_guid(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    const char  *busname = "org.openbmc.control.Chassis";
    const char  *objname = "/org/openbmc/control/chassis0";
    const char  *iface = "org.openbmc.control.Chassis";
    sd_bus_message *reply = NULL, *m = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int r = 0;
    char *uuid = NULL;

    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;

    printf("IPMI GET DEVICE GUID\n");

    r = sd_bus_message_new_method_call(bus,&m,busname,objname,iface,"getID");
    if (r < 0) {
        fprintf(stderr, "Failed to add the start method object: %s\n", strerror(-r));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    r = sd_bus_call(bus, m, 0, &error, &reply);
    if (r < 0) {
        fprintf(stderr, "Failed to call the start method: %s\n", strerror(-r));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    r = sd_bus_message_read(reply, "s", &uuid);
    if (r < 0) {
        fprintf(stderr, "Failed to get a response: %s", strerror(-r));
        return IPMI_CC_RESPONSE_ERROR;
    }
    if (uuid == NULL)
    {
        fprintf(stderr, "Failed to get a valid response: %s", strerror(-r));
        return IPMI_CC_RESPONSE_ERROR;
    }

    // UUID is in RFC4122 format. Ex: 61a39523-78f2-11e5-9862-e6402cfc3223
    // Per IPMI Spec 2.0 need to convert to 16 hex bytes and reverse the byte order
    // Ex: 0x2332fc2c40e66298e511f2782395a361

    const int resp_size = 16; // Response is 16 hex bytes per IPMI Spec
    uint8_t resp_uuid[resp_size]; // Array to hold the formatted response
    int resp_loc = resp_size-1; // Point resp end of array to save in reverse order
    int i = 0;
    char *tokptr = NULL;

    // Traverse the UUID
    char* id_octet = strtok_r(uuid, "-", &tokptr); // Get the UUID octects separated by dash

    if (id_octet == NULL)
    { // Error
        fprintf(stderr, "Unexpected UUID format: %s", uuid);
        return IPMI_CC_RESPONSE_ERROR;
    }

    while (id_octet != NULL)
    {
        // Calculate the octet string size since it varies
        // Divide it by 2 for the array size since 1 byte is built from 2 chars
        int tmp_size = strlen(id_octet)/2;

        for(i = 0; i < tmp_size; i++)
        {
            char tmp_array[3]; // Holder of the 2 chars that will become a byte
            tmp_array[3] = '\0';
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

    sd_bus_error_free(&error);
    sd_bus_message_unref(m);

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
    const char  *busname = "org.openbmc.watchdog.Host";
    const char  *objname = "/org/openbmc/watchdog/HostWatchdog_0";
    const char  *iface = "org.openbmc.Watchdog";
    sd_bus_message *reply = NULL, *m = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int r = 0;

    set_wd_data_t *reqptr = (set_wd_data_t*) request;
    uint16_t timer = 0;
    uint32_t timer_ms = 0;
    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;

    *data_len = 0;

    // Get number of 100ms intervals
    timer = (((uint16_t)reqptr->ms) << 8) + reqptr->ls;
    // Get timer value in ms
    timer_ms = timer * 100;

    printf("WATCHDOG SET Timer:[0x%X] 100ms intervals\n",timer);

    // Set watchdog timer
    r = sd_bus_message_new_method_call(bus,&m,busname,objname,iface,"set");
    if (r < 0) {
        fprintf(stderr, "Failed to add the set method object: %s\n", strerror(-r));
        return -1;
    }
    r = sd_bus_message_append(m, "i", timer_ms);
    if (r < 0) {
        fprintf(stderr, "Failed to add timer value: %s\n", strerror(-r));
        return -1;
    }
    r = sd_bus_call(bus, m, 0, &error, &reply);
    if (r < 0) {
        fprintf(stderr, "Failed to call the set method: %s\n", strerror(-r));
        return -1;
    }

    // Stop the current watchdog if any
    r = sd_bus_message_new_method_call(bus,&m,busname,objname,iface,"stop");
    if (r < 0) {
        fprintf(stderr, "Failed to add the start method object: %s\n", strerror(-r));
        return -1;
    }
    r = sd_bus_call(bus, m, 0, &error, &reply);
    if (r < 0) {
        fprintf(stderr, "Failed to call the start method: %s\n", strerror(-r));
        return -1;
    }

    // Start the watchdog if requested
    if (reqptr->t_use & 0x40)
    {
        r = sd_bus_message_new_method_call(bus,&m,busname,objname,iface,"start");
        if (r < 0) {
            fprintf(stderr, "Failed to add the start method object: %s\n", strerror(-r));
            return -1;
        }
        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0) {
            fprintf(stderr, "Failed to call the start method: %s\n", strerror(-r));
            return -1;
        }
    }

    sd_bus_error_free(&error);
    sd_bus_message_unref(m);

    return rc;
}


ipmi_ret_t ipmi_app_reset_watchdog(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    const char  *busname = "org.openbmc.watchdog.Host";
    const char  *objname = "/org/openbmc/watchdog/HostWatchdog_0";
    const char  *iface = "org.openbmc.Watchdog";
    sd_bus_message *reply = NULL, *m = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int r = 0;

    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;

    printf("WATCHDOG RESET\n");

    // Refresh watchdog
    r = sd_bus_message_new_method_call(bus,&m,busname,objname,iface,"poke");
    if (r < 0) {
        fprintf(stderr, "Failed to add the method object: %s\n", strerror(-r));
        return -1;
    }
    r = sd_bus_call(bus, m, 0, &error, &reply);
    if (r < 0) {
        fprintf(stderr, "Failed to call the method: %s\n", strerror(-r));
        return -1;
    }

    sd_bus_error_free(&error);
    sd_bus_message_unref(m);

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

    return;
}


