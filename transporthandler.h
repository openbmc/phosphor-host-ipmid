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
static const int LAN_PARM_VLAN        = 20;
static const int MAX_VLAN_ID = 4095;

struct ChannelConfig_t
{
    std::string ipaddr;
    std::string netmask;
    std::string gateway;
    std::string macAddress;
    // IPMI stores the vlan info in 16 bits,32 bits is to aligned
    // with phosphor-dbus interfaces.
    // vlan id is in 12 bits and the 16th bit is for enable mask.
    uint32_t vlanID = MAX_VLAN_ID;
};

#endif
