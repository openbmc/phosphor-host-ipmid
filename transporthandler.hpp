#pragma once

#include "types.hpp"

#include <string>
// IPMI commands for Transport net functions.
enum ipmi_netfn_storage_cmds
{
    // Get capability bits
    IPMI_CMD_SET_LAN = 0x01,
    IPMI_CMD_GET_LAN = 0x02,
    IPMI_CMD_SET_SOL_CONF_PARAMS = 0x21,
    IPMI_CMD_GET_SOL_CONF_PARAMS = 0x22,
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
    AUTHSUPPORT = 1, // Read-only
    AUTHENABLES = 2,
    IP = 3,
    IPSRC = 4,
    MAC = 5,
    SUBNET = 6,
    IPHEADER_PARAMS = 7,
    RMCP_PORT = 8,
    RMCP_SECONDARY_PORT = 9,
    BMC_GENERATED_ARP_CTRL = 10,
    GRATUITOUS_ARP_INTERVAL = 11,
    GATEWAY = 12,
    GATEWAY_MAC = 13,
    GATEWAY_BACKUP = 14,
    GATEWAY_BACKUP_MAC = 15,
    COMMUNITY_STRING = 16,
    LAN_ALERT_DESTINATION_COUNT = 17, // Read-only
    LAN_ALERT_DESTINATION_TYPE = 18,  // Type per destination
    LAN_ALERT_DESTINATIONS = 19,
    VLAN = 20,
    VLAN_PRIORITY = 21,
    CIPHER_SUITE_COUNT = 22,   // Read-only
    CIPHER_SUITE_ENTRIES = 23, // Read-only
    CIPHER_SUITE_PRIVILEGE_LEVELS = 24,
    DESTINATION_ADDR_VLAN_TAGS = 25,
    BAD_PASSWORD_THRESHOLD = 26,
    IPV6_AND_IPV4_SUPPORTED = 50, // Read-only
    IPV6_AND_IPV4_ENABLES = 51,
    IPV6_HEADER_STATIC_TRAFFIC_CLASS = 52,
    IPV6_HEADER_STATIC_HOP_LIMIT = 53,
    IPV6_HEADER_FLOW_LABEL = 54,
    IPV6_STATUS = 55, // Read-only
    IPV6_STATIC_ADDRESSES = 56,
    IPV6_DHCPV6_STATIC_DUID_STORAGE_LENGTH = 57, // Read-only
    IPV6_DHCPV6_STATIC_DUIDS = 58,
    IPV6_DYNAMIC_ADDRESSES = 59,            // Read-only
    IPV6_DHCPV6_DYNAMIC_DUID_STOR_LEN = 60, // Read-only
    IPV6_DHCPV6_DYNAMIC_DUIDS = 61,
    IPV6_DHCPV6_TIMING_CONF_SUPPORT = 62, // Read-only
    IPV6_DHCPV6_TIMING_CONFIGURATION = 63,
    IPV6_ROUTER_ADDRESS_CONF_CTRL = 64,
    IPV6_STATIC_ROUTER_1_IP_ADDR = 65,
    IPV6_STATIC_ROUTER_1_MAC_ADDR = 66,
    IPV6_STATIC_ROUTER_1_PREFIX_LEN = 67,
    IPV6_STATIC_ROUTER_1_PREFIX_VAL = 68,
    IPV6_STATIC_ROUTER_2_IP_ADDR = 69,
    IPV6_STATIC_ROUTER_2_MAC_ADDR = 70,
    IPV6_STATIC_ROUTER_2_PREFIX_LEN = 71,
    IPV6_STATIC_ROUTER_2_PREFIX_VAL = 72,
    DYNAMIC_ROUTER_INFO_SET_COUNT = 73,       // Read-only
    IPV6_DYNAMIC_ROUTER_INFO_IP_ADDR = 74,    // Read-only
    IPV6_DYNAMIC_ROUTER_INFO_MAC = 75,        // Read-only
    IPV6_DYNAMIC_ROUTER_INFO_PREFIX_LEN = 76, // Read-only
    IPV6_DYNAMIC_ROUTER_INFO_PREFIX_VAL = 77, // Read-only
    IPV6_DYNAMIC_ROUTER_RECV_HOP_LIMIT = 78,
    IPV6_NEIGHBOR_TIMING_CONF_SUPPORT = 79, // Read-only
    IPV6_NEIGHBOR_TIMING_CONFIGURATION = 80,
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

namespace sol
{

enum class Parameter
{
    progress,       //!< Set In Progress.
    enable,         //!< SOL Enable.
    authentication, //!< SOL Authentication.
    accumulate,     //!< Character Accumulate Interval & Send Threshold.
    retry,          //!< SOL Retry.
    nvbitrate,      //!< SOL non-volatile bit rate.
    vbitrate,       //!< SOL volatile bit rate.
    channel,        //!< SOL payload channel.
    port,           //!< SOL payload port.
};

enum class Privilege : uint8_t
{
    highestPriv,
    callbackPriv,
    userPriv,
    operatorPriv,
    adminPriv,
    oemPriv,
};

} // namespace sol

constexpr uint8_t progressMask = 0x03;
constexpr uint8_t enableMask = 0x01;

struct Auth
{
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t privilege : 4; //!< SOL privilege level.
    uint8_t reserved : 2;  //!< Reserved.
    uint8_t auth : 1;      //!< Force SOL payload Authentication.
    uint8_t encrypt : 1;   //!< Force SOL payload encryption.
#endif

#if BYTE_ORDER == BIG_ENDIAN
    uint8_t encrypt : 1;   //!< Force SOL payload encryption.
    uint8_t auth : 1;      //!< Force SOL payload Authentication.
    uint8_t reserved : 2;  //!< Reserved.
    uint8_t privilege : 4; //!< SOL privilege level.
#endif
} __attribute__((packed));

struct Accumulate
{
    uint8_t interval;  //!< Character accumulate interval.
    uint8_t threshold; //!< Character send threshold.
} __attribute__((packed));

struct Retry
{
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t count : 3;    //!< SOL retry count.
    uint8_t reserved : 5; //!< Reserved.
#endif

#if BYTE_ORDER == BIG_ENDIAN
    uint8_t reserved : 5; //!< Reserved.
    uint8_t count : 3;    //!< SOL retry count.
#endif

    uint8_t interval; //!< SOL retry interval.
} __attribute__((packed));

struct SetConfParamsRequest
{
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t channelNumber : 4; //!< Channel number.
    uint8_t reserved : 4;      //!< Reserved.
#endif

#if BYTE_ORDER == BIG_ENDIAN
    uint8_t reserved : 4;      //!< Reserved.
    uint8_t channelNumber : 4; //!< Channel number.
#endif

    uint8_t paramSelector; //!< Parameter selector.
    union
    {
        uint8_t value;         //!< Represents one byte SOL parameters.
        struct Accumulate acc; //!< Character accumulate values.
        struct Retry retry;    //!< Retry values.
        struct Auth auth;      //!< Authentication parameters.
    };
} __attribute__((packed));

struct SetConfParamsResponse
{
    uint8_t completionCode; //!< Completion code.
} __attribute__((packed));

struct GetConfParamsRequest
{
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t channelNum : 4;  //!< Channel number.
    uint8_t reserved : 3;    //!< Reserved.
    uint8_t getParamRev : 1; //!< Get parameter or Get parameter revision
#endif

#if BYTE_ORDER == BIG_ENDIAN
    uint8_t getParamRev : 1; //!< Get parameter or Get parameter revision
    uint8_t reserved : 3;    //!< Reserved.
    uint8_t channelNum : 4;  //!< Channel number.
#endif

    uint8_t paramSelector; //!< Parameter selector.
    uint8_t setSelector;   //!< Set selector.
    uint8_t blockSelector; //!< Block selector.
} __attribute__((packed));

struct GetConfParamsResponse
{
    uint8_t completionCode; //!< Completion code.
    uint8_t paramRev;       //!< Parameter revision.
} __attribute__((packed));
