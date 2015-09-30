#ifndef __HOST_IPMI_APP_HANDLER_H__
#define __HOST_IPMI_APP_HANDLER_H__

// IPMI commands for net functions.
enum ipmi_netfn_app_cmds
{
    // Get capability bits
    IPMI_CMD_GET_CAP_BIT    = 0x36,
};

#endif
