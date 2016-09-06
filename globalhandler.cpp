#include "globalhandler.h"
#include "host-ipmid/ipmid-api.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <mapper.h>

const char  *control_object_name  =  "/org/openbmc/control/bmc0";
const char  *control_intf_name    =  "org.openbmc.control.Bmc";

void register_netfn_global_functions() __attribute__((constructor));

int dbus_reset(const char *method)
{
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *m = NULL;
    sd_bus *bus = NULL;
    char* connection = NULL;
    int r;

    bus = ipmid_get_sd_bus_connection();
    r = mapper_get_service(bus, control_object_name, &connection);
    if (r < 0) {
        fprintf(stderr, "Failed to get connection for %s: %s\n",
                control_object_name, strerror(-r));
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
    // Cold Reset
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_COLD_RESET);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_COLD_RESET, NULL, ipmi_global_cold_reset,
                           PRIVILEGE_ADMIN);

    // <Warm Reset>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_WARM_RESET);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_WARM_RESET, NULL, ipmi_global_warm_reset,
                           PRIVILEGE_ADMIN);

    return;
}
