#pragma once

#include "types.hpp"

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
enum class LanParam : uint8_t
{
    INPROGRESS = 0,
    AUTHSUPPORT = 1,
    AUTHENABLES = 2,
    IP = 3,
    IPSRC = 4,
    MAC = 5,
    SUBNET = 6,
    GATEWAY = 12,
    VLAN = 20,
    CIPHER_SUITE_COUNT = 22,
    CIPHER_SUITE_ENTRIES = 23,
};

constexpr uint8_t SET_COMPLETE = 0;
constexpr uint8_t SET_IN_PROGRESS = 1;
constexpr uint8_t SET_COMMIT_WRITE = 2;         // Optional
constexpr uint8_t SET_IN_PROGRESS_RESERVED = 3; // Reserved

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
    bool flushForSetComplete = false;
    bool flush = false;

    void clear()
    {
        ipaddr.clear();
        netmask.clear();
        gateway.clear();
        macAddress.clear();
        vlanID = ipmi::network::VLAN_ID_MASK;
        ipsrc = ipmi::network::IPOrigin::UNSPECIFIED;
        lan_set_in_progress = SET_COMPLETE;
        flushForSetComplete = false;
        flush = false;
    }
};

// Given a channel, get the corresponding configuration,
// or allocate it first.
//
// @param[in] channel the channel
// @return the ChannelConfig_t pointer.
struct ChannelConfig_t* getChannelConfig(int channel);

/** @brief Iterate over all the channelconfig and if
 *         user has given the data for a channel then
 *         apply the network changes for that channel.
 */
void commitNetworkChanges();

/* @brief  Apply the network changes which is there in the
 *         network cache for a given channel which gets filled
 *         through setLan command. If some of the network
 *         parameter was not given by the setLan then this function
 *         gets the value of that parameter which is already
 *         configured on the system.
 * @param[in] channel: channel number.
 */
void applyChanges(int channel);
