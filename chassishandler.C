#include "chassishandler.h"
#include "ipmid-api.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

void register_netfn_chassis_functions() __attribute__((constructor));

struct get_sys_boot_options_t {
    uint8_t parameter;
    uint8_t set;
    uint8_t block;
}  __attribute__ ((packed));

ipmi_ret_t ipmi_chassis_wildcard(ipmi_netfn_t netfn, ipmi_cmd_t cmd, 
                              ipmi_request_t request, ipmi_response_t response, 
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    printf("Handling CHASSIS WILDCARD Netfn:[0x%X], Cmd:[0x%X]\n",netfn, cmd);
    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;
    return rc;
}

ipmi_ret_t ipmi_chassis_get_sys_boot_options(ipmi_netfn_t netfn, ipmi_cmd_t cmd, 
                              ipmi_request_t request, ipmi_response_t response, 
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;

    printf("IPMI GET_SYS_BOOT_OPTIONS\n");

    get_sys_boot_options_t *reqptr = (get_sys_boot_options_t*) request;

    // TODO Return default values to OPAL until dbus interface is available

    if (reqptr->parameter == 5) // Parameter #5
    {
        uint8_t buf[] = {0x1,0x5,80,0,0,0,0};
        *data_len = sizeof(buf);
        memcpy(response, &buf, *data_len);
    }
    else
    {
        fprintf(stderr, "Unsupported parameter 0x%x\n", reqptr->parameter);
        return IPMI_CC_PARM_NOT_SUPPORTED;        
    }

    return rc;
}

void register_netfn_chassis_functions()
{
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_CHASSIS, IPMI_CMD_WILDCARD);
    ipmi_register_callback(NETFUN_CHASSIS, IPMI_CMD_WILDCARD, NULL, ipmi_chassis_wildcard);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_CHASSIS, IPMI_CMD_GET_SYS_BOOT_OPTIONS);
    ipmi_register_callback(NETFUN_CHASSIS, IPMI_CMD_GET_SYS_BOOT_OPTIONS, NULL, ipmi_chassis_get_sys_boot_options);
}

