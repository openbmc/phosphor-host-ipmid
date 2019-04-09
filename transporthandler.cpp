#include "transporthandler.hpp"

#include "app/channel.hpp"
#include "user_channel/channel_layer.hpp"

#include <arpa/inet.h>
#include <endian.h>
#include <netinet/ether.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/message/types.hpp>
#include <sdbusplus/timer.hpp>
#include <string>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/Network/IP/server.hpp>

// timer for network changes
std::unique_ptr<phosphor::Timer> networkTimer = nullptr;

std::map<int, std::unique_ptr<struct ChannelConfig_t>> channelConfig;

using sdbusplus::xyz::openbmc_project::Network::server::IP;

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

namespace fs = std::filesystem;
namespace variant_ns = sdbusplus::message::variant_ns;

void register_netfn_transport_functions() __attribute__((constructor));

struct ChannelConfig_t* getChannelConfig(int channel)
{
    auto item = channelConfig.find(channel);
    if (item == channelConfig.end())
    {
        channelConfig[channel] = std::make_unique<struct ChannelConfig_t>();
    }

    return channelConfig[channel].get();
}

/** @brief The dbus parameters for the interface corresponding to a channel
 *         This helps reduce the number of mapper lookups we need for each
 *         query and simplifies finding the VLAN interface if needed.
 */
struct ChannelParams
{
    /** @brief The channel ID */
    int id;
    /** @brief channel name for the interface */
    std::string ifname;
    /** @brief Name of the service on the bus */
    std::string service;
    /** @brief Lower level adapter path that is guaranteed to not be a VLAN */
    std::string ifPath;
    /** @brief Logical adapter path used for address assignment */
    std::string logicalPath;
};

/** @brief Determines the ethernet interface name corresponding to a channel
 *         Tries to map a VLAN object first so that the address information
 *         is accurate. Otherwise it gets the standard ethernet interface.
 *
 *  @param[in] bus     - The bus object used for lookups
 *  @param[in] channel - The channel id corresponding to an ethernet interface
 *  @return Ethernet interface service and object path if it exists
 */
std::optional<ChannelParams> getChannelParams(sdbusplus::bus::bus& bus,
                                              int channel)
{
    auto ifname = ipmi::getChannelName(channel);
    if (ifname.empty())
    {
        return std::nullopt;
    }

    // Enumerate all VLAN + ETHERNET interfaces
    auto req = bus.new_method_call(ipmi::MAPPER_BUS_NAME, ipmi::MAPPER_OBJ,
                                   ipmi::MAPPER_INTF, "GetSubTree");
    req.append(ipmi::network::ROOT, 0,
               std::vector<std::string>{ipmi::network::VLAN_INTERFACE,
                                        ipmi::network::ETHERNET_INTERFACE});
    auto reply = bus.call(req);
    ipmi::ObjectTree objs;
    reply.read(objs);

    ChannelParams params;
    for (const auto& [path, impls] : objs)
    {
        if (path.find(ifname) == path.npos)
        {
            continue;
        }
        for (const auto& [service, intfs] : impls)
        {
            bool vlan = false;
            bool ethernet = false;
            for (const auto& intf : intfs)
            {
                if (intf == ipmi::network::VLAN_INTERFACE)
                {
                    vlan = true;
                }
                else if (intf == ipmi::network::ETHERNET_INTERFACE)
                {
                    ethernet = true;
                }
            }
            if (params.service.empty() && (vlan || ethernet))
            {
                params.service = service;
            }
            if (params.ifPath.empty() && !vlan && ethernet)
            {
                params.ifPath = path;
            }
            if (params.logicalPath.empty() && vlan)
            {
                params.logicalPath = path;
            }
        }
    }
    // We must have a path for the underlying interface
    if (params.ifPath.empty())
    {
        return std::nullopt;
    }
    // We don't have a VLAN so the logical path is the same
    if (params.logicalPath.empty())
    {
        params.logicalPath = params.ifPath;
    }

    params.id = channel;
    params.ifname = std::move(ifname);
    return std::move(params);
}

/** @brief Wraps the phosphor logging method to insert some additional metadata
 *
 *  @param[in] params - The parameters for the channel on the ethernet interface
 *  ...
 */
template <auto level, typename... Args>
auto logWithChannel(const ChannelParams& params, Args&&... args)
{
    return log<level>(std::forward<Args>(args)...,
                      entry("CHANNEL=%d", params.id),
                      entry("IFNAME=%s", params.ifname.c_str()));
}
template <auto level, typename... Args>
auto logWithChannel(const std::optional<ChannelParams>& params, Args&&... args)
{
    if (params)
    {
        return logWithChannel<level>(*params, std::forward<Args>(args)...);
    }
    return log<level>(std::forward<Args>(args)...);
}

/** @brief Gets the vlan ID configured on the interface
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel on the ethernet interface
 *  @return VLAN id or the standard 0 for no VLAN
 */
uint16_t getVLAN(sdbusplus::bus::bus& bus, const ChannelParams& params)
{
    if (params.ifPath == params.logicalPath)
    {
        return 0;
    }

    auto vlan = std::get<uint32_t>(
        ipmi::getDbusProperty(bus, params.service, params.logicalPath,
                              ipmi::network::VLAN_INTERFACE, "Id"));
    if ((vlan & ipmi::network::VLAN_VALUE_MASK) != vlan)
    {
        logWithChannel<level::ERR>(params, "networkd returned an invalid vlan",
                                   entry("VLAN=%" PRIu32, vlan));
        elog<InternalFailure>();
    }
    return vlan;
}

/** @brief Determines if the ethernet interface is using DHCP
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel on the ethernet interface
 *  @return True if DHCP is enabled, false otherwise
 */
bool getDHCPProperty(sdbusplus::bus::bus& bus, const ChannelParams& params)
{
    return std::get<bool>(ipmi::getDbusProperty(
        bus, params.service, params.logicalPath,
        ipmi::network::ETHERNET_INTERFACE, "DHCPEnabled"));
}

/** @brief Retrieves the current gateway for the address family on the system
 *         NOTE: The gateway is currently system wide and not per channel
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel on the ethernet interface
 *  @param[in] family - The address family of the gateway
 *  @return A string representing the gateway address
 */
std::string getGatewayProperty(sdbusplus::bus::bus& bus,
                               const ChannelParams& params, int family)
{
    std::string member;
    switch (family)
    {
        case AF_INET:
            member = "DefaultGateway";
            break;
        case AF_INET6:
            member = "DefaultGateway6";
            break;
        default:
            log<level::ERR>("Bad Gateway Family", entry("FAMILY=%d", family));
            elog<InternalFailure>();
    }

    return std::get<std::string>(ipmi::getDbusProperty(
        bus, params.service, ipmi::network::SYSTEMCONFIG_PATH,
        ipmi::network::SYSTEMCONFIG_INTERFACE, member));
}

/** @brief Gets the address info configured for the interface at the specified
 *         index. NOTE: This lacks stability across address changes since
 *         the network daemon has no notion of stable indicies.
 *
 *  @param[in] bus      - The bus object used for lookups
 *  @param[in] params   - The parameters for the channel on the ethernet
 *                        interface
 *  @param[in] selector - Determines which address to lookup
 *  @return The address and prefix if it was found
 */
std::optional<IfAddr> getIfAddr(sdbusplus::bus::bus& bus,
                                const ChannelParams& params,
                                const IfAddrSelector& selector)
{
    std::string filter;
    switch (selector.family)
    {
        case AF_INET:
            filter = "ipv4";
            break;
        case AF_INET6:
            filter = "ipv6";
            break;
        default:
            log<level::ERR>("Bad IP Origin",
                            entry("FAMILY=%d", selector.family));
            elog<InternalFailure>();
    }

    ipmi::ObjectTree objs = ipmi::getAllDbusObjects(
        bus, params.logicalPath, ipmi::network::IP_INTERFACE, filter);
    uint8_t idx = 0;
    for (const auto& obj : objs)
    {
        ipmi::PropertyMap properties =
            ipmi::getAllDbusProperties(bus, obj.second.begin()->first,
                                       obj.first, ipmi::network::IP_INTERFACE);

        IP::AddressOrigin origin = IP::convertAddressOriginFromString(
            std::get<std::string>(properties.at("Origin")));
        if (selector.origins.find(origin) == selector.origins.end())
        {
            continue;
        }

        if (idx < selector.idx)
        {
            idx++;
            continue;
        }

        IfAddr ifaddr;
        ifaddr.address = std::get<std::string>(properties.at("Address"));
        ifaddr.prefix = std::get<uint8_t>(properties.at("PrefixLength"));
        ifaddr.origin = origin;
        return std::move(ifaddr);
    }

    return std::nullopt;
}

/** @brief Turns a prefix into a netmask
 *
 *  @param[in] prefix - The prefix length
 *  @return The netmask
 */
in_addr prefixToNetmask(uint8_t prefix)
{
    if (prefix > 32)
    {
        log<level::ERR>("Invalid prefix");
        elog<InternalFailure>();
    }
    return {htobe32(~UINT32_C(0) << (32 - prefix))};
}

/** @brief Turns a a netmask into a prefix length
 *
 *  @param[in] netmask - The netmask in byte form
 *  @return The prefix length
 */
uint8_t netmaskToPrefix(in_addr netmask)
{
    uint32_t x = be32toh(netmask.s_addr);
    if ((~x & (~x + 1)) != 0)
    {
        log<level::ERR>("Invalid netmask");
        elog<InternalFailure>();
    }
    return 32 - __builtin_ctz(x);
}

// Helper Function to get IP Address/NetMask/Gateway/MAC Address from Network
// Manager or Cache based on Set-In-Progress State
ipmi_ret_t getNetworkData(uint8_t lan_param, uint8_t* data, int channel)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    std::optional<ChannelParams> params;

    try
    {
        sdbusplus::bus::bus bus(ipmid_get_sd_bus_connection());

        params = getChannelParams(bus, channel);
        if (!params)
        {
            // TODO: return error from getNetworkData()
            return IPMI_CC_INVALID_FIELD_REQUEST;
        }
        auto channelConf = getChannelConfig(channel);
        IfAddrSelector selector;
        selector.family = AF_INET;
        selector.origins = {IP::AddressOrigin::Static, IP::AddressOrigin::DHCP};
        selector.idx = 0;

        switch (static_cast<LanParam>(lan_param))
        {
            case LanParam::IP:
            {
                std::string ipaddress;
                if (channelConf->ipaddr.empty())
                {
                    auto ifaddr = getIfAddr(bus, *params, selector);
                    if (ifaddr)
                    {
                        ipaddress = ifaddr->address;
                    }
                }
                else
                {
                    ipaddress = channelConf->ipaddr;
                }

                if (ipaddress.empty())
                {
                    // There is no return code for empty values so return
                    // an empty address.
                    break;
                }
                if (inet_pton(AF_INET, ipaddress.c_str(), data) != 1)
                {
                    logWithChannel<level::ERR>(
                        params, "Got a bad ip from network daemon",
                        entry("IP=%s", ipaddress.c_str()));
                    elog<InternalFailure>();
                }
            }
            break;

            case LanParam::IPSRC:
            {
                bool dhcpEnabled;
                if (!channelConf->dhcpEnabled)
                {
                    dhcpEnabled = getDHCPProperty(bus, *params);
                }
                else
                {
                    dhcpEnabled = *channelConf->dhcpEnabled;
                }

                auto ipsrc = dhcpEnabled ? ipmi::network::IPOrigin::DHCP
                                         : ipmi::network::IPOrigin::STATIC;
                std::memcpy(data, &ipsrc, ipmi::network::IPSRC_SIZE_BYTE);
            }
            break;

            case LanParam::SUBNET:
            {
                uint8_t prefix = DEFAULT_PREFIX;
                if (channelConf->prefix == UNSET_PREFIX)
                {
                    auto ifaddr = getIfAddr(bus, *params, selector);
                    if (ifaddr)
                    {
                        prefix = ifaddr->prefix;
                    }
                }
                else
                {
                    prefix = channelConf->prefix;
                }

                in_addr netmask = prefixToNetmask(prefix);
                std::memcpy(data, &netmask, sizeof(netmask));
            }
            break;

            case LanParam::GATEWAY:
            {
                auto gateway = getGatewayProperty(bus, *params, AF_INET);
                if (gateway.empty())
                {
                    // There is no return code for empty values so return
                    // an empty address.
                    break;
                }
                if (inet_pton(AF_INET, gateway.c_str(), data) != 1)
                {
                    logWithChannel<level::ERR>(
                        params, "Got a bad gateway from network daemon",
                        entry("GATEWAY=%s", gateway.c_str()));
                    elog<InternalFailure>();
                }
            }
            break;

            case LanParam::MAC:
            {
                auto macStr = std::get<std::string>(ipmi::getDbusProperty(
                    bus, params->service, params->ifPath,
                    ipmi::network::MAC_INTERFACE, "MACAddress"));
                const struct ether_addr* mac = ether_aton(macStr.c_str());
                if (mac == nullptr)
                {
                    log<level::ERR>("Got a bad MAC from network daemon");
                    elog<InternalFailure>();
                }
                std::memcpy(data, mac, sizeof(struct ether_addr));
            }
            break;

            case LanParam::VLAN:
            {
                uint16_t vlan;
                if (!channelConf->vlan)
                {
                    vlan = getVLAN(bus, *params);
                    if (vlan != 0)
                    {
                        vlan |= ipmi::network::VLAN_ENABLE_FLAG;
                    }
                }
                else
                {
                    vlan = std::get<uint16_t>(*channelConf->vlan);
                    if (std::get<bool>(*channelConf->vlan))
                    {
                        vlan |= ipmi::network::VLAN_ENABLE_FLAG;
                    }
                }
                vlan = htole16(vlan);
                std::memcpy(data, &vlan, sizeof(vlan));
            }
            break;

            default:
                rc = IPMI_CC_PARM_OUT_OF_RANGE;
        }
    }
    catch (const InternalFailure& e)
    {
        commit<InternalFailure>();
        rc = IPMI_CC_UNSPECIFIED_ERROR;
    }
    catch (const std::exception& e)
    {
        logWithChannel<level::ERR>(params, "Failed to get network data",
                                   entry("PARAMETER=%" PRIu8, lan_param),
                                   entry("ERROR=%s", e.what()));
        commit<InternalFailure>();
        rc = IPMI_CC_UNSPECIFIED_ERROR;
    }
    return rc;
}

namespace cipher
{

std::vector<uint8_t> getCipherList()
{
    std::vector<uint8_t> cipherList;

    std::ifstream jsonFile(configFile);
    if (!jsonFile.is_open())
    {
        log<level::ERR>("Channel Cipher suites file not found");
        elog<InternalFailure>();
    }

    auto data = Json::parse(jsonFile, nullptr, false);
    if (data.is_discarded())
    {
        log<level::ERR>("Parsing channel cipher suites JSON failed");
        elog<InternalFailure>();
    }

    // Byte 1 is reserved
    cipherList.push_back(0x00);

    for (const auto& record : data)
    {
        cipherList.push_back(record.value(cipher, 0));
    }

    return cipherList;
}

} // namespace cipher

ipmi_ret_t ipmi_transport_wildcard(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                   ipmi_request_t request,
                                   ipmi_response_t response,
                                   ipmi_data_len_t data_len,
                                   ipmi_context_t context)
{
    // Status code.
    ipmi_ret_t rc = IPMI_CC_INVALID;
    *data_len = 0;
    return rc;
}

struct set_lan_t
{
    uint8_t channel;
    uint8_t parameter;
    uint8_t data[8]; // Per IPMI spec, not expecting more than this size
} __attribute__((packed));

ipmi_ret_t checkAndUpdateNetwork(int channel)
{
    auto channelConf = getChannelConfig(channel);
    using namespace std::chrono_literals;
    // time to wait before applying the network changes.
    constexpr auto networkTimeout = 10000000us; // 10 sec

    // Skip the timer. Expecting more update as we are in SET_IN_PROGRESS
    if (channelConf->lan_set_in_progress == SET_IN_PROGRESS)
    {
        return IPMI_CC_OK;
    }

    // Start the timer, if it is direct single param update without
    // SET_IN_PROGRESS or many params updated through SET_IN_PROGRESS to
    // SET_COMPLETE Note: Even for update with SET_IN_PROGRESS, don't apply the
    // changes immediately, as ipmitool sends each param individually
    // through SET_IN_PROGRESS to SET_COMPLETE.
    channelConf->flush = true;
    if (!networkTimer)
    {
        log<level::ERR>("Network timer is not instantiated");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    // start the timer.
    networkTimer->start(networkTimeout);
    return IPMI_CC_OK;
}

ipmi_ret_t ipmi_transport_set_lan(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                  ipmi_request_t request,
                                  ipmi_response_t response,
                                  ipmi_data_len_t data_len,
                                  ipmi_context_t context)
{
    *data_len = 0;

    auto reqptr = reinterpret_cast<const set_lan_t*>(request);
    sdbusplus::bus::bus bus(ipmid_get_sd_bus_connection());

    // channel number is the lower nibble
    int channel = reqptr->channel & CHANNEL_MASK;
    auto channelConf = getChannelConfig(channel);

    switch (static_cast<LanParam>(reqptr->parameter))
    {
        case LanParam::IP:
        {
            char ipaddr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, reqptr->data, ipaddr, sizeof(ipaddr));
            channelConf->ipaddr = ipaddr;
            return checkAndUpdateNetwork(channel);
        }

        case LanParam::IPSRC:
        {
            ipmi::network::IPOrigin ipsrc;
            std::memcpy(&ipsrc, reqptr->data, ipmi::network::IPSRC_SIZE_BYTE);
            switch (ipsrc)
            {
                case ipmi::network::IPOrigin::DHCP:
                    channelConf->dhcpEnabled = true;
                    break;
                case ipmi::network::IPOrigin::STATIC:
                    channelConf->dhcpEnabled = false;
                    break;
                default:
                    return IPMI_CC_PARM_NOT_SUPPORTED;
            }
            return checkAndUpdateNetwork(channel);
        }

        case LanParam::MAC:
        {
            struct ether_addr mac;
            std::memcpy(&mac, reqptr->data, sizeof(mac));
            std::string macStr = ether_ntoa(&mac);
            try
            {
                auto params = getChannelParams(bus, channel);
                if (!params)
                {
                    return IPMI_CC_INVALID_FIELD_REQUEST;
                }
                ipmi::setDbusProperty(bus, params->service, params->ifPath,
                                      ipmi::network::MAC_INTERFACE,
                                      "MACAddress", macStr);
                return IPMI_CC_OK;
            }
            catch (...)
            {
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
        }

        case LanParam::SUBNET:
        {
            try
            {
                in_addr netmask;
                std::memcpy(&netmask, reqptr->data, sizeof(netmask));
                channelConf->prefix = netmaskToPrefix(netmask);
                return checkAndUpdateNetwork(channel);
            }
            catch (...)
            {
                return IPMI_CC_INVALID_FIELD_REQUEST;
            }
        }

        case LanParam::GATEWAY:
        {
            char gateway[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, reqptr->data, gateway, sizeof(gateway));
            auto sysObj =
                ipmi::getDbusObject(bus, ipmi::network::SYSTEMCONFIG_INTERFACE,
                                    ipmi::network::ROOT);
            ipmi::setDbusProperty(bus, sysObj.second, sysObj.first,
                                  ipmi::network::SYSTEMCONFIG_INTERFACE,
                                  "DefaultGateway", std::string(gateway));
            return IPMI_CC_OK;
        }

        case LanParam::VLAN:
        {
            uint16_t vlan;
            std::memcpy(&vlan, reqptr->data, sizeof(vlan));
            vlan = le16toh(vlan);
            channelConf->vlan.emplace(vlan & ipmi::network::VLAN_ENABLE_FLAG,
                                      vlan & ipmi::network::VLAN_VALUE_MASK);
            return checkAndUpdateNetwork(channel);
        }

        case LanParam::INPROGRESS:
        {
            if (reqptr->data[0] == SET_COMPLETE)
            {
                channelConf->lan_set_in_progress = SET_COMPLETE;
            }
            else if (reqptr->data[0] == SET_IN_PROGRESS) // Set In Progress
            {
                channelConf->lan_set_in_progress = SET_IN_PROGRESS;
            }
            return checkAndUpdateNetwork(channel);
        }

        default:
            return IPMI_CC_PARM_NOT_SUPPORTED;
    }

    return IPMI_CC_UNSPECIFIED_ERROR;
}

struct get_lan_t
{
    uint8_t rev_channel;
    uint8_t parameter;
    uint8_t parameter_set;
    uint8_t parameter_block;
} __attribute__((packed));

ipmi_ret_t ipmi_transport_get_lan(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                  ipmi_request_t request,
                                  ipmi_response_t response,
                                  ipmi_data_len_t data_len,
                                  ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;
    const uint8_t current_revision = 0x11; // Current rev per IPMI Spec 2.0

    get_lan_t* reqptr = (get_lan_t*)request;
    // channel number is the lower nibble
    int channel = reqptr->rev_channel & CHANNEL_MASK;

    if (reqptr->rev_channel & 0x80) // Revision is bit 7
    {
        // Only current revision was requested
        *data_len = sizeof(current_revision);
        std::memcpy(response, &current_revision, *data_len);
        return IPMI_CC_OK;
    }

    static std::vector<uint8_t> cipherList;
    static auto listInit = false;

    if (!listInit)
    {
        try
        {
            cipherList = cipher::getCipherList();
            listInit = true;
        }
        catch (const std::exception& e)
        {
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
    }

    LanParam param = static_cast<LanParam>(reqptr->parameter);
    switch (param)
    {
        case LanParam::INPROGRESS:
        {
            auto channelConf = getChannelConfig(channel);
            uint8_t buf[] = {current_revision,
                             channelConf->lan_set_in_progress};
            *data_len = sizeof(buf);
            std::memcpy(response, &buf, *data_len);
            break;
        }
        case LanParam::AUTHSUPPORT:
        {
            uint8_t buf[] = {current_revision, 0x04};
            *data_len = sizeof(buf);
            std::memcpy(response, &buf, *data_len);
            break;
        }
        case LanParam::AUTHENABLES:
        {
            uint8_t buf[] = {current_revision, 0x04, 0x04, 0x04, 0x04, 0x04};
            *data_len = sizeof(buf);
            std::memcpy(response, &buf, *data_len);
            break;
        }
        case LanParam::IP:
        case LanParam::SUBNET:
        case LanParam::GATEWAY:
        case LanParam::MAC:
        {
            uint8_t buf[ipmi::network::MAC_ADDRESS_SIZE_BYTE + 1] = {};

            *data_len = sizeof(current_revision);
            std::memcpy(buf, &current_revision, *data_len);

            if (getNetworkData(reqptr->parameter, &buf[1], channel) ==
                IPMI_CC_OK)
            {
                if (param == LanParam::MAC)
                {
                    *data_len = sizeof(buf);
                }
                else
                {
                    *data_len = ipmi::network::IPV4_ADDRESS_SIZE_BYTE + 1;
                }
                std::memcpy(response, &buf, *data_len);
            }
            else
            {
                rc = IPMI_CC_UNSPECIFIED_ERROR;
            }
            break;
        }
        case LanParam::VLAN:
        {
            uint8_t buf[ipmi::network::VLAN_SIZE_BYTE + 1] = {};

            *data_len = sizeof(current_revision);
            std::memcpy(buf, &current_revision, *data_len);
            if (getNetworkData(reqptr->parameter, &buf[1], channel) ==
                IPMI_CC_OK)
            {
                *data_len = sizeof(buf);
                std::memcpy(response, &buf, *data_len);
            }
            break;
        }
        case LanParam::IPSRC:
        {
            uint8_t buff[ipmi::network::IPSRC_SIZE_BYTE + 1] = {};
            *data_len = sizeof(current_revision);
            std::memcpy(buff, &current_revision, *data_len);
            if (getNetworkData(reqptr->parameter, &buff[1], channel) ==
                IPMI_CC_OK)
            {
                *data_len = sizeof(buff);
                std::memcpy(response, &buff, *data_len);
            }
            break;
        }
        case LanParam::CIPHER_SUITE_COUNT:
        {
            *(static_cast<uint8_t*>(response)) = current_revision;
            // Byte 1 is reserved byte and does not indicate a cipher suite ID,
            // so no of cipher suite entry count is one less than the size of
            // the vector
            auto count = static_cast<uint8_t>(cipherList.size() - 1);
            *(static_cast<uint8_t*>(response) + 1) = count;
            *data_len = sizeof(current_revision) + sizeof(count);
            break;
        }
        case LanParam::CIPHER_SUITE_ENTRIES:
        {
            *(static_cast<uint8_t*>(response)) = current_revision;
            // Byte 1 is reserved
            std::copy_n(cipherList.data(), cipherList.size(),
                        static_cast<uint8_t*>(response) + 1);
            *data_len = sizeof(current_revision) +
                        static_cast<uint8_t>(cipherList.size());
            break;
        }
        default:
            log<level::ERR>("Unsupported parameter",
                            entry("PARAMETER=0x%x", reqptr->parameter));
            rc = IPMI_CC_PARM_NOT_SUPPORTED;
    }

    return rc;
}

/** @brief Populates configuration information for the channel if it is missing
 *         and is going to be used for the state transition.
 *
 *  @param[in]     bus      - The bus object used for lookups
 *  @param[in]     params   - The parameters for the channel
 *  @param[in,out] conf     - The current configuration which will be updated
 */
void populateChannelConf(sdbusplus::bus::bus& bus, const ChannelParams& params,
                         ChannelConfig_t& conf)
{
    if (!conf.vlan)
    {
        conf.vlan.emplace(true, getVLAN(bus, params));
    }

    if (!conf.dhcpEnabled)
    {
        conf.dhcpEnabled = getDHCPProperty(bus, params);
    }

    // Only populate address info if we are going to use it
    if (!*conf.dhcpEnabled)
    {
        IfAddrSelector selector;
        selector.family = AF_INET;
        // We only want to copy bits from previous static configs
        selector.origins = {IP::AddressOrigin::Static};
        selector.idx = 0;
        auto ifaddr = getIfAddr(params, selector);

        if (ifaddr)
        {
            if (conf.ipaddr.empty())
            {
                conf.ipaddr = ifaddr->address;
            }
            if (conf.prefix == UNSET_PREFIX)
            {
                conf.prefix = ifaddr->prefix;
            }
        }
    }
}

/** @brief Deletes all customizations from an interface
 *
 *  @param[in]     bus    - The bus object used for reset
 *  @param[in,out] params - The parameters for the channel
 */
void resetChannel(sdbusplus::bus::bus& bus, ChannelParams& params)
{
    // First clear out configured properties
    ipmi::setDbusProperty(bus, params.service, params.ifPath,
                          ipmi::network::ETHERNET_INTERFACE, "DHCPEnabled",
                          false);

    // Delete all objects associated with the interface
    auto objreq = bus.new_method_call(ipmi::MAPPER_BUS_NAME, ipmi::MAPPER_OBJ,
                                      ipmi::MAPPER_INTF, "GetSubTree");
    objreq.append(ipmi::network::ROOT, 0,
                  std::vector<std::string>{ipmi::DELETE_INTERFACE});
    auto objreply = bus.call(objreq);
    ipmi::ObjectTree objs;
    objreply.read(objs);
    for (const auto& [path, impls] : objs)
    {
        if (path.find(params.ifname) == path.npos)
        {
            continue;
        }
        for (const auto& [service, intfs] : impls)
        {
            auto delreq = bus.new_method_call(service.c_str(), path.c_str(),
                                              ipmi::DELETE_INTERFACE, "Delete");
            bus.call_noreply(delreq);
        }
        // Update params to reflect the deletion of vlan
        if (path == params.logicalPath)
        {
            params.logicalPath = params.ifPath;
        }
    }
}

/** @brief Applies the configuration information for the channel
 *
 *  @param[in]     bus    - The bus object used for reset
 *  @param[in,out] params - The parameters for the channel
 *  @param[in]     conf   - The new configuration for the channel
 */
void applyConfig(sdbusplus::bus::bus& bus, ChannelParams& params,
                 const ChannelConfig_t& conf)
{
    // We need the new VLAN interface first
    const auto& vlan = conf.vlan.value();
    if (std::get<bool>(vlan) && std::get<uint16_t>(vlan) != 0)
    {
        ipmi::network::createVLAN(bus, ipmi::network::SERVICE,
                                  ipmi::network::ROOT, params.ifname,
                                  std::get<uint16_t>(vlan));
    }

    // Ensure we are up to date with VLAN interface changes
    auto newParams = getChannelParams(params.id);
    if (!newParams)
    {
        logWithChannel<level::ERR>(params,
                                   "Failed to get new channel parameters");
        elog<InternalFailure>();
    }
    params = *newParams;

    // Configure the interface
    ipmi::setDbusProperty(bus, params.service, params.logicalPath,
                          ipmi::network::ETHERNET_INTERFACE, "DHCPEnabled",
                          conf.dhcpEnabled.value());

    if (!conf.ipaddr.empty() && !conf.dhcpEnabled.value())
    {
        auto prefix =
            conf.prefix == UNSET_PREFIX ? DEFAULT_PREFIX : conf.prefix;
        auto protocol =
            sdbusplus::xyz::openbmc_project::Network::server::convertForMessage(
                IP::Protocol::IPv4);
        ipmi::network::createIP(bus, params.service, params.logicalPath,
                                protocol, conf.ipaddr, prefix);
    }
}

void commitNetworkChanges()
{
    sdbusplus::bus::bus bus(ipmid_get_sd_bus_connection());
    std::optional<ChannelParams> params;

    for (const auto& [channel, conf] : channelConfig)
    {
        if (!conf->flush)
        {
            continue;
        }

        try
        {
            params = getChannelParams(channel);
            if (!params)
            {
                log<level::ERR>("Unable to get channel params for commit",
                                entry("CHANNEL=%d", channel));
                elog<InternalFailure>();
            }

            populateChannelConf(bus, *params, *conf);
            resetChannel(bus, *params);
            applyConfig(bus, *params, *conf);
        }
        catch (const InternalFailure&)
        {
            commit<InternalFailure>();
        }
        catch (const std::exception& e)
        {
            logWithChannel<level::ERR>(params, "Failed to commit network data",
                                       entry("ERROR=%s", e.what()));
            commit<InternalFailure>();
        }
        conf->clear();
    }
}

void createNetworkTimer()
{
    if (!networkTimer)
    {
        networkTimer = std::make_unique<phosphor::Timer>(&commitNetworkChanges);
    }
}

void register_netfn_transport_functions()
{
    // As this timer is only for transport handler
    // so creating it here.
    createNetworkTimer();
    // <Wildcard Command>
    ipmi_register_callback(NETFUN_TRANSPORT, IPMI_CMD_WILDCARD, NULL,
                           ipmi_transport_wildcard, PRIVILEGE_USER);

    // <Set LAN Configuration Parameters>
    ipmi_register_callback(NETFUN_TRANSPORT, IPMI_CMD_SET_LAN, NULL,
                           ipmi_transport_set_lan, PRIVILEGE_ADMIN);

    // <Get LAN Configuration Parameters>
    ipmi_register_callback(NETFUN_TRANSPORT, IPMI_CMD_GET_LAN, NULL,
                           ipmi_transport_get_lan, PRIVILEGE_OPERATOR);

    return;
}
