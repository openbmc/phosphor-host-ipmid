#ifndef __HOST_IPMI_SEN_HANDLER_H__
#define __HOST_IPMI_SEN_HANDLER_H__

// IPMI commands for net functions.
enum ipmi_netfn_sen_cmds
{
    // Get capability bits
    IPMI_CMD_GET_SENSOR_TYPE = 0x2F,
    IPMI_CMD_SET_SENSOR      = 0x30,

};

#endif
