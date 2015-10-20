#ifndef __HOST_IPMI_APP_HANDLER_H__
#define __HOST_IPMI_APP_HANDLER_H__

// IPMI commands for App net functions.
enum ipmi_netfn_app_cmds
{
    // Get capability bits
    IPMI_CMD_GET_DEVICE_ID          = 0x01,
    IPMI_CMD_SET_ACPI               = 0x06,
    IPMI_CMD_RESET_WD               = 0x22,
    IPMI_CMD_SET_WD                 = 0x24,
    IPMI_CMD_SET_BMC_GLOBAL_ENABLES = 0x2E,
    IPMI_CMD_READ_EVENT             = 0x35,
    IPMI_CMD_GET_CAP_BIT            = 0x36,

};

#endif
