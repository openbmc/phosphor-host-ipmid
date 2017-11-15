#pragma once

#include "types.hpp"
#include <memory>
#include <string>

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
static const int LAN_PARM_IPSRC       = 4;
static const int LAN_PARM_MAC         = 5;
static const int LAN_PARM_SUBNET      = 6;
static const int LAN_PARM_GATEWAY     = 12;
static const int LAN_PARM_VLAN        = 20;

const uint8_t SET_COMPLETE = 0;
const uint8_t SET_IN_PROGRESS = 1;
const uint8_t SET_COMMIT_WRITE = 2; //Optional
const uint8_t SET_IN_PROGRESS_RESERVED = 3; //Reserved

const int CHANNEL_MASK = 0x0f;
const int NUM_CHANNELS = 0x0f;

struct ChannelConfig_t
{
    std::string ipaddr;
    ipmi::network::IPOrigin ipsrc = ipmi::network::IPOrigin::UNSPECIFIED;
    std::string netmask;
    std::string gateway;
    std::string macAddress;
    // IPMI stores the vlan info in 16 bits,32 bits is to aligned
    // with phosphor-dbus interfaces.
    // vlan id is in 12 bits and the 16th bit is for enable mask.
    uint32_t vlanID = ipmi::network::VLAN_ID_MASK;
    uint8_t lan_set_in_progress = SET_COMPLETE;

    void clear()
    {
        ipaddr.clear();
        netmask.clear();
        gateway.clear();
        macAddress.clear();
        vlanID = ipmi::network::VLAN_ID_MASK;
        ipsrc = ipmi::network::IPOrigin::UNSPECIFIED;
        lan_set_in_progress = SET_COMPLETE;
    }
};

// Given a channel, get the corresponding configuration,
// or allocate it first.
//
// @param[in] channel the channel
// @return the ChannelConfig_t pointer.
struct ChannelConfig_t* getChannelConfig(int channel);
