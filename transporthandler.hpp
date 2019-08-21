#pragma once

#include <ipmid/api.hpp>
#include <ipmid/types.hpp>
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
    LAN_OEM1 = 192,
    LAN_OEM2 = 193,
    LAN_OEM3 = 194,
    LAN_OEM4 = 195,
    LAN_OEM5 = 196,
    LAN_OEM6 = 197,
    LAN_OEM7 = 198,
    LAN_OEM8 = 199,
    LAN_OEM9 = 200,
    LAN_OEM10 = 201,
    LAN_OEM11 = 202,
    LAN_OEM12 = 203,
    LAN_OEM13 = 204,
    LAN_OEM14 = 205,
    LAN_OEM15 = 206,
    LAN_OEM16 = 207,
    LAN_OEM17 = 208,
    LAN_OEM18 = 209,
    LAN_OEM19 = 210,
    LAN_OEM20 = 211,
    LAN_OEM21 = 212,
    LAN_OEM22 = 213,
    LAN_OEM23 = 214,
    LAN_OEM24 = 215,
    LAN_OEM25 = 216,
    LAN_OEM26 = 217,
    LAN_OEM27 = 218,
    LAN_OEM28 = 219,
    LAN_OEM29 = 220,
    LAN_OEM30 = 221,
    LAN_OEM31 = 222,
    LAN_OEM32 = 223,
    LAN_OEM33 = 224,
    LAN_OEM34 = 225,
    LAN_OEM35 = 226,
    LAN_OEM36 = 227,
    LAN_OEM37 = 228,
    LAN_OEM38 = 229,
    LAN_OEM39 = 230,
    LAN_OEM40 = 231,
    LAN_OEM41 = 232,
    LAN_OEM42 = 233,
    LAN_OEM43 = 234,
    LAN_OEM44 = 235,
    LAN_OEM45 = 236,
    LAN_OEM46 = 237,
    LAN_OEM47 = 238,
    LAN_OEM48 = 239,
    LAN_OEM49 = 240,
    LAN_OEM50 = 241,
    LAN_OEM51 = 242,
    LAN_OEM52 = 243,
    LAN_OEM53 = 244,
    LAN_OEM54 = 245,
    LAN_OEM55 = 246,
    LAN_OEM56 = 247,
    LAN_OEM57 = 248,
    LAN_OEM58 = 249,
    LAN_OEM59 = 250,
    LAN_OEM60 = 251,
    LAN_OEM61 = 252,
    LAN_OEM62 = 253,
    LAN_OEM63 = 254,
    LAN_OEM64 = 255
};

// Data length of parameters
constexpr size_t lanParamVLANSize = 4;
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

/******************************************************************************
 * Define placeholder command handlers for the OEM Extension bytes for the Set
 * LAN Configuration Parameters and Get LAN Configuration Parameters commands.
 * To create handlers for your own proprietary command set:
 *   Create/modify a phosphor-ipmi-host Bitbake append file within your Yocto
 *   recipe
 *   Insert EXTRA_OEMAKE lines
 *      EXTRA_OEMAKE += "ipmid_OEM_OVERRIDE=-DOVERRIDE_TRANSPORT_OEM_EXTENSIONS"
 *      EXTRA_OEMAKE += "libipmi20_la_SOURCES+=transporthandler_oem.cpp"
 *      ... repeat as necessary
 *   Create C++ file(s) that define IPMI handler functions matching the
 *     function names below (i.e. ipmi_transport_set_lan_oem)
 *   Place the new file(s) into your Bitbake append SRC_URI list
 ******************************************************************************/
#ifdef OVERRIDE_TRANSPORT_OEM_EXTENSIONS
ipmi_ret_t ipmi_transport_set_lan_oem(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                      ipmi_request_t request,
                                      ipmi_response_t response,
                                      ipmi_data_len_t data_len,
                                      ipmi_context_t context);

ipmi_ret_t ipmi_transport_get_lan_oem(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                      ipmi_request_t request,
                                      ipmi_response_t response,
                                      ipmi_data_len_t data_len,
                                      ipmi_context_t context);
#endif

constexpr uint16_t maxValidVLANIDValue = 4095;
