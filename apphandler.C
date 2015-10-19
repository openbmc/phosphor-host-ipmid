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

    // Start watchdog
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

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_SET_ACPI);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_SET_ACPI, NULL, ipmi_app_set_acpi_power_state);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_READ_EVENT);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_READ_EVENT, NULL, ipmi_app_read_event);
    return;
}


