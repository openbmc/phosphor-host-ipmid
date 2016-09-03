#include "dcmihandler.h"
#include "host-ipmid/ipmid-api.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

void register_netfn_dcmi_functions() __attribute__((constructor));


ipmi_ret_t ipmi_dcmi_get_power_limit(ipmi_netfn_t netfn, ipmi_cmd_t cmd, 
                              ipmi_request_t request, ipmi_response_t response, 
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_DCMI_CC_NO_ACTIVE_POWER_LIMIT;

    // dcmi-v1-5-rev-spec.pdf 6.6.2.   
    // This is good enough for OpenBMC support for OpenPOWER based systems
    // TODO research if more is needed
    uint8_t data_response[] = { 0xDC, 0x00, 0x00, 0x01, 0x00, 0x00, 
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                                0x00, 0x01};



    printf("IPMI DCMI_GET_POWER_LEVEL\n");

    memcpy(response, data_response, sizeof(data_response));
    *data_len = sizeof(data_response);

    return rc;
}


void register_netfn_dcmi_functions()
{
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_GRPEXT, IPMI_CMD_DCMI_GET_POWER);
    ipmi_register_callback(NETFUN_GRPEXT, IPMI_CMD_DCMI_GET_POWER, NULL, ipmi_dcmi_get_power_limit);
    return;
}
// 956379