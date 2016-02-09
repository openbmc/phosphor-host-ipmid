#ifndef __HOST_IPMI_TRANSPORT_HANDLER_H__
#define __HOST_IPMI_TRANSPORT_HANDLER_H__

// IPMI commands for Transport net functions.
enum ipmi_netfn_storage_cmds
{
    // Get capability bits
    IPMI_CMD_SET_LAN = 0x01,
    IPMI_CMD_GET_LAN = 0x02,
};

// Command specific completion codes
enum ipmi_transport_return_codes
{
    IPMI_CC_PARM_NOT_SUPPORTED = 0x80,
};

// Parameters
static const int LAN_PARM_INPROGRESS  = 0;
static const int LAN_PARM_AUTHSUPPORT = 1;
static const int LAN_PARM_AUTHENABLES = 2;
static const int LAN_PARM_IP          = 3;
static const int LAN_PARM_MAC         = 5;
static const int LAN_PARM_SUBNET      = 6;
static const int LAN_PARM_GATEWAY     = 12;

#endif
