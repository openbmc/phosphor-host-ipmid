#ifndef __HOST_IPMI_CHASSIS_HANDLER_H__
#define __HOST_IPMI_CHASSIS_HANDLER_H__

// IPMI commands for Chassis net functions.
enum ipmi_netfn_app_cmds
{
    // Get capability bits
    IPMI_CMD_GET_SYS_BOOT_OPTIONS = 0x09,
};

// Command specific completion codes
enum ipmi_chassis_return_codes
{
    IPMI_CC_PARM_NOT_SUPPORTED = 0x80,
};

#endif
