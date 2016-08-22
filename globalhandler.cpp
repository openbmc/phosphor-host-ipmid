#include "globalhandler.h"
#include "host-ipmid/ipmid-api.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

const char  *control_object_name  =  "/org/openbmc/control/bmc0";
const char  *control_intf_name    =  "org.openbmc.control.Bmc";

const char  *objectmapper_service_name =  "org.openbmc.ObjectMapper";
const char  *objectmapper_object_name  =  "/org/openbmc/ObjectMapper";
const char  *objectmapper_intf_name    =  "org.openbmc.ObjectMapper";

void register_netfn_global_functions() __attribute__((constructor));

int obj_mapper_get_connection(char** buf, const char* obj_path)
{
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *m = NULL;
    sd_bus *bus = NULL;
    char *temp_buf = NULL, *intf = NULL;
    size_t buf_size = 0;
    int r;

    //Get the system bus where most system services are provided.
    bus = ipmid_get_sd_bus_connection();

    /*
     * Bus, service, object path, interface and method are provided to call
     * the method.
     * Signatures and input arguments are provided by the arguments at the
     * end.
     */
    r = sd_bus_call_method(bus,
            objectmapper_service_name,                      /* service to contact */
            objectmapper_object_name,                       /* object path */
            objectmapper_intf_name,                         /* interface name */
            "GetObject",                                    /* method name */
            &error,                                         /* object to return error in */
            &m,                                             /* return message on success */
            "s",                                            /* input signature */
            obj_path                                        /* first argument */
            );

    if (r < 0) {
        fprintf(stderr, "Failed to issue method call: %s\n", error.message);
        goto finish;
    }

    // Get the key, aka, the connection name
    sd_bus_message_read(m, "a{sas}", 1, &temp_buf, 1, &intf);
    
	/* 
     * TODO: check the return code. Currently for no reason the message
     * parsing of object mapper is always complaining about
     * "Device or resource busy", but the result seems OK for now. Need
     *  further checks.
     */

    buf_size = strlen(temp_buf) + 1;
    printf("IPMID connection name: %s\n", temp_buf);
    *buf = (char*)malloc(buf_size);

    if (*buf == NULL) {
        fprintf(stderr, "Malloc failed for warm reset");
        r = -1;
        goto finish;
    }

    memcpy(*buf, temp_buf, buf_size);

finish:
    sd_bus_error_free(&error);
    sd_bus_message_unref(m);

    return r;
}


int dbus_reset(const char *method)
{
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *m = NULL;
    sd_bus *bus = NULL;
    char* connection = NULL;
    int r;

    r = obj_mapper_get_connection(&connection, control_object_name);
    if (r < 0) {
        fprintf(stderr, "Failed to get connection, return value: %d.\n", r);
        goto finish;
    }

    printf("connection: %s\n", connection);

    // Open the system bus where most system services are provided.
    bus = ipmid_get_sd_bus_connection();
    
    /*
     * Bus, service, object path, interface and method are provided to call
     * the method.
     * Signatures and input arguments are provided by the arguments at the
     * end.
     */
    r = sd_bus_call_method(bus,
            connection,                                /* service to contact */
            control_object_name,                       /* object path */
            control_intf_name,                         /* interface name */
            method,                               /* method name */
            &error,                                    /* object to return error in */
            &m,                                        /* return message on success */
            NULL,
            NULL
            );

    if (r < 0) {
        fprintf(stderr, "Failed to issue method call: %s\n", error.message);
        goto finish;
    }

finish:
    sd_bus_error_free(&error);
    sd_bus_message_unref(m);
    free(connection);

    return r;
}

ipmi_ret_t ipmi_global_warm_reset(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    printf("Handling GLOBAL warmReset Netfn:[0x%X], Cmd:[0x%X]\n",netfn, cmd);

    // TODO: call the correct dbus method for warmReset.
    dbus_reset("warmReset");

    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;
    return rc;
}

ipmi_ret_t ipmi_global_cold_reset(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    printf("Handling GLOBAL coldReset Netfn:[0x%X], Cmd:[0x%X]\n",netfn, cmd);

    // TODO: call the correct dbus method for coldReset.
    dbus_reset("coldReset");

    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;
    return rc;
}

void register_netfn_global_functions()
{
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_COLD_RESET);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_COLD_RESET, NULL, ipmi_global_cold_reset);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_WARM_RESET);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_WARM_RESET, NULL, ipmi_global_warm_reset);

    return;
}
