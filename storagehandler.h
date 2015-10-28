#ifndef __HOST_IPMI_STORAGE_HANDLER_H__
#define __HOST_IPMI_STORAGE_HANDLER_H__

// IPMI commands for Storage net functions.
enum ipmi_netfn_storage_cmds
{
    // Get capability bits
    IPMI_CMD_WRITE_FRU_DATA = 0x12,
    IPMI_CMD_GET_SEL_INFO   = 0x40,
    IPMI_CMD_RESERVE_SEL    = 0x42,
    IPMI_CMD_ADD_SEL        = 0x44,
    IPMI_CMD_GET_SEL_TIME   = 0x48,
    IPMI_CMD_SET_SEL_TIME   = 0x49,

};

#endif
