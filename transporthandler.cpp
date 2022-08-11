#include "transporthandler.hpp"

using phosphor::logging::commit;
using phosphor::logging::elog;
using phosphor::logging::entry;
using phosphor::logging::level;
using phosphor::logging::log;
using sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
using sdbusplus::xyz::openbmc_project::Network::server::EthernetInterface;
using sdbusplus::xyz::openbmc_project::Network::server::IP;
using sdbusplus::xyz::openbmc_project::Network::server::Neighbor;

namespace cipher
{

std::vector<uint8_t> getCipherList()
{
    std::vector<uint8_t> cipherList;

    std::ifstream jsonFile(cipher::configFile);
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

namespace ipmi
{
namespace transport
{

/** @brief Valid address origins for IPv4 */
const std::unordered_set<IP::AddressOrigin> originsV4 = {
    IP::AddressOrigin::Static,
    IP::AddressOrigin::DHCP,
};

static constexpr uint8_t oemCmdStart = 192;
static constexpr uint8_t oemCmdEnd = 255;

std::optional<ChannelParams> maybeGetChannelParams(sdbusplus::bus_t& bus,
                                                   uint8_t channel)
{
    auto ifname = getChannelName(channel);
    if (ifname.empty())
    {
        return std::nullopt;
    }

    // Enumerate all VLAN + ETHERNET interfaces
    auto req = bus.new_method_call(MAPPER_BUS_NAME, MAPPER_OBJ, MAPPER_INTF,
                                   "GetSubTree");
    req.append(PATH_ROOT, 0,
               std::vector<std::string>{INTF_VLAN, INTF_ETHERNET});
    auto reply = bus.call(req);
    ObjectTree objs;
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
                if (intf == INTF_VLAN)
                {
                    vlan = true;
                }
                else if (intf == INTF_ETHERNET)
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
    return params;
}

ChannelParams getChannelParams(sdbusplus::bus_t& bus, uint8_t channel)
{
    auto params = maybeGetChannelParams(bus, channel);
    if (!params)
    {
        log<level::ERR>("Failed to get channel params",
                        entry("CHANNEL=%" PRIu8, channel));
        elog<InternalFailure>();
    }
    return std::move(*params);
}

/** @brief Wraps the phosphor logging method to insert some additional metadata
 *
 *  @param[in] params - The parameters for the channel
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

EthernetInterface::DHCPConf getDHCPProperty(sdbusplus::bus_t& bus,
                                            const ChannelParams& params)
{
    std::string dhcpstr = std::get<std::string>(getDbusProperty(
        bus, params.service, params.logicalPath, INTF_ETHERNET, "DHCPEnabled"));
    return EthernetInterface::convertDHCPConfFromString(dhcpstr);
}

/** @brief Sets the DHCP v4 state on the given interface
 *
 *  @param[in] bus           - The bus object used for lookups
 *  @param[in] params        - The parameters for the channel
 *  @param[in] requestedDhcp - DHCP state to assign
 *                             (EthernetInterface::DHCPConf::none,
 *                              EthernetInterface::DHCPConf::v4,
 *                              EthernetInterface::DHCPConf::v6,
 *                              EthernetInterface::DHCPConf::both)
 */
void setDHCPv4Property(sdbusplus::bus_t& bus, const ChannelParams& params,
                       const EthernetInterface::DHCPConf requestedDhcp)
{
    EthernetInterface::DHCPConf currentDhcp = getDHCPProperty(bus, params);
    EthernetInterface::DHCPConf nextDhcp = EthernetInterface::DHCPConf::none;

    // When calling setDHCPv4Property, requestedDhcp only has "v4" and "none".
    // setDHCPv4Property is only for IPv4 management. It should not modify
    // IPv6 state.
    if (requestedDhcp == EthernetInterface::DHCPConf::v4)
    {
        if ((currentDhcp == EthernetInterface::DHCPConf::v6) ||
            (currentDhcp == EthernetInterface::DHCPConf::both))
            nextDhcp = EthernetInterface::DHCPConf::both;
        else if ((currentDhcp == EthernetInterface::DHCPConf::v4) ||
                 (currentDhcp == EthernetInterface::DHCPConf::none))
            nextDhcp = EthernetInterface::DHCPConf::v4;
    }
    else if (requestedDhcp == EthernetInterface::DHCPConf::none)
    {
        if ((currentDhcp == EthernetInterface::DHCPConf::v6) ||
            (currentDhcp == EthernetInterface::DHCPConf::both))
            nextDhcp = EthernetInterface::DHCPConf::v6;
        else if ((currentDhcp == EthernetInterface::DHCPConf::v4) ||
                 (currentDhcp == EthernetInterface::DHCPConf::none))
            nextDhcp = EthernetInterface::DHCPConf::none;
    }
    else // Stay the same.
    {
        nextDhcp = currentDhcp;
    }
    std::string newDhcp =
        sdbusplus::xyz::openbmc_project::Network::server::convertForMessage(
            nextDhcp);
    setDbusProperty(bus, params.service, params.logicalPath, INTF_ETHERNET,
                    "DHCPEnabled", newDhcp);
}

void setDHCPv6Property(sdbusplus::bus_t& bus, const ChannelParams& params,
                       const EthernetInterface::DHCPConf requestedDhcp,
                       const bool defaultMode = true)
{
    EthernetInterface::DHCPConf currentDhcp = getDHCPProperty(bus, params);
    EthernetInterface::DHCPConf nextDhcp = EthernetInterface::DHCPConf::none;

    if (defaultMode)
    {
        // When calling setDHCPv6Property, requestedDhcp only has "v6" and
        // "none".
        // setDHCPv6Property is only for IPv6 management. It should not modify
        // IPv4 state.
        if (requestedDhcp == EthernetInterface::DHCPConf::v6)
        {
            if ((currentDhcp == EthernetInterface::DHCPConf::v4) ||
                (currentDhcp == EthernetInterface::DHCPConf::both))
                nextDhcp = EthernetInterface::DHCPConf::both;
            else if ((currentDhcp == EthernetInterface::DHCPConf::v6) ||
                     (currentDhcp == EthernetInterface::DHCPConf::none))
                nextDhcp = EthernetInterface::DHCPConf::v6;
        }
        else if (requestedDhcp == EthernetInterface::DHCPConf::none)
        {
            if ((currentDhcp == EthernetInterface::DHCPConf::v4) ||
                (currentDhcp == EthernetInterface::DHCPConf::both))
                nextDhcp = EthernetInterface::DHCPConf::v4;
            else if ((currentDhcp == EthernetInterface::DHCPConf::v6) ||
                     (currentDhcp == EthernetInterface::DHCPConf::none))
                nextDhcp = EthernetInterface::DHCPConf::none;
        }
        else // Stay the same.
        {
            nextDhcp = currentDhcp;
        }
    }
    else
    {
        // allow the v6 call to set any value
        nextDhcp = requestedDhcp;
    }

    std::string newDhcp =
        sdbusplus::xyz::openbmc_project::Network::server::convertForMessage(
            nextDhcp);
    setDbusProperty(bus, params.service, params.logicalPath, INTF_ETHERNET,
                    "DHCPEnabled", newDhcp);
}

ether_addr stringToMAC(const char* mac)
{
    const ether_addr* ret = ether_aton(mac);
    if (ret == nullptr)
    {
        log<level::ERR>("Invalid MAC Address", entry("MAC=%s", mac));
        elog<InternalFailure>();
    }
    return *ret;
}

/** @brief Determines the MAC of the ethernet interface
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel
 *  @return The configured mac address
 */
ether_addr getMACProperty(sdbusplus::bus_t& bus, const ChannelParams& params)
{
    auto macStr = std::get<std::string>(getDbusProperty(
        bus, params.service, params.ifPath, INTF_MAC, "MACAddress"));
    return stringToMAC(macStr.c_str());
}

/** @brief Sets the system value for MAC address on the given interface
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel
 *  @param[in] mac    - MAC address to apply
 */
void setMACProperty(sdbusplus::bus_t& bus, const ChannelParams& params,
                    const ether_addr& mac)
{
    std::string macStr = ether_ntoa(&mac);
    setDbusProperty(bus, params.service, params.ifPath, INTF_MAC, "MACAddress",
                    macStr);
}

void deleteObjectIfExists(sdbusplus::bus_t& bus, const std::string& service,
                          const std::string& path)
{
    if (path.empty())
    {
        return;
    }
    try
    {
        auto req = bus.new_method_call(service.c_str(), path.c_str(),
                                       ipmi::DELETE_INTERFACE, "Delete");
        bus.call_noreply(req);
    }
    catch (const sdbusplus::exception_t& e)
    {
        if (strcmp(e.name(),
                   "xyz.openbmc_project.Common.Error.InternalFailure") != 0 &&
            strcmp(e.name(), "org.freedesktop.DBus.Error.UnknownObject") != 0)
        {
            // We want to rethrow real errors
            throw;
        }
    }
}

/** @brief Sets the address info configured for the interface
 *         If a previous address path exists then it will be removed
 *         before the new address is added.
 *
 *  @param[in] bus     - The bus object used for lookups
 *  @param[in] params  - The parameters for the channel
 *  @param[in] address - The address of the new IP
 *  @param[in] prefix  - The prefix of the new IP
 */
template <int family>
void createIfAddr(sdbusplus::bus_t& bus, const ChannelParams& params,
                  const typename AddrFamily<family>::addr& address,
                  uint8_t prefix)
{
    auto newreq =
        bus.new_method_call(params.service.c_str(), params.logicalPath.c_str(),
                            INTF_IP_CREATE, "IP");
    std::string protocol =
        sdbusplus::xyz::openbmc_project::Network::server::convertForMessage(
            AddrFamily<family>::protocol);
    newreq.append(protocol, addrToString<family>(address), prefix, "");
    bus.call_noreply(newreq);
}

/** @brief Trivial helper for getting the IPv4 address from getIfAddrs()
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel
 *  @return The address and prefix if found
 */
auto getIfAddr4(sdbusplus::bus_t& bus, const ChannelParams& params)
{
    return getIfAddr<AF_INET>(bus, params, 0, originsV4);
}

/** @brief Reconfigures the IPv4 address info configured for the interface
 *
 *  @param[in] bus     - The bus object used for lookups
 *  @param[in] params  - The parameters for the channel
 *  @param[in] address - The new address if specified
 *  @param[in] prefix  - The new address prefix if specified
 */
void reconfigureIfAddr4(sdbusplus::bus_t& bus, const ChannelParams& params,
                        const std::optional<in_addr>& address,
                        std::optional<uint8_t> prefix)
{
    auto ifaddr = getIfAddr4(bus, params);
    if (!ifaddr && !address)
    {
        log<level::ERR>("Missing address for IPv4 assignment");
        elog<InternalFailure>();
    }
    uint8_t fallbackPrefix = AddrFamily<AF_INET>::defaultPrefix;
    if (ifaddr)
    {
        fallbackPrefix = ifaddr->prefix;
        deleteObjectIfExists(bus, params.service, ifaddr->path);
    }
    createIfAddr<AF_INET>(bus, params, address.value_or(ifaddr->address),
                          prefix.value_or(fallbackPrefix));
}

template <int family>
std::optional<IfNeigh<family>> findGatewayNeighbor(sdbusplus::bus_t& bus,
                                                   const ChannelParams& params,
                                                   ObjectLookupCache& neighbors)
{
    auto gateway = getGatewayProperty<family>(bus, params);
    if (!gateway)
    {
        return std::nullopt;
    }

    return findStaticNeighbor<family>(bus, params, *gateway, neighbors);
}

template <int family>
std::optional<IfNeigh<family>> getGatewayNeighbor(sdbusplus::bus_t& bus,
                                                  const ChannelParams& params)
{
    ObjectLookupCache neighbors(bus, params, INTF_NEIGHBOR);
    return findGatewayNeighbor<family>(bus, params, neighbors);
}

template <int family>
void reconfigureGatewayMAC(sdbusplus::bus_t& bus, const ChannelParams& params,
                           const ether_addr& mac)
{
    auto gateway = getGatewayProperty<family>(bus, params);
    if (!gateway)
    {
        log<level::ERR>("Tried to set Gateway MAC without Gateway");
        elog<InternalFailure>();
    }

    ObjectLookupCache neighbors(bus, params, INTF_NEIGHBOR);
    auto neighbor =
        findStaticNeighbor<family>(bus, params, *gateway, neighbors);
    if (neighbor)
    {
        deleteObjectIfExists(bus, params.service, neighbor->path);
    }

    createNeighbor<family>(bus, params, *gateway, mac);
}

/** @brief Deconfigures the IPv6 address info configured for the interface
 *
 *  @param[in] bus     - The bus object used for lookups
 *  @param[in] params  - The parameters for the channel
 *  @param[in] idx     - The address index to operate on
 */
void deconfigureIfAddr6(sdbusplus::bus_t& bus, const ChannelParams& params,
                        uint8_t idx)
{
    auto ifaddr = getIfAddr<AF_INET6>(bus, params, idx, originsV6Static);
    if (ifaddr)
    {
        deleteObjectIfExists(bus, params.service, ifaddr->path);
    }
}

/** @brief Reconfigures the IPv6 address info configured for the interface
 *
 *  @param[in] bus     - The bus object used for lookups
 *  @param[in] params  - The parameters for the channel
 *  @param[in] idx     - The address index to operate on
 *  @param[in] address - The new address
 *  @param[in] prefix  - The new address prefix
 */
void reconfigureIfAddr6(sdbusplus::bus_t& bus, const ChannelParams& params,
                        uint8_t idx, const in6_addr& address, uint8_t prefix)
{
    deconfigureIfAddr6(bus, params, idx);
    createIfAddr<AF_INET6>(bus, params, address, prefix);
}

/** @brief Converts the AddressOrigin into an IPv6Source
 *
 *  @param[in] origin - The DBus Address Origin to convert
 *  @return The IPv6Source version of the origin
 */
IPv6Source originToSourceType(IP::AddressOrigin origin)
{
    switch (origin)
    {
        case IP::AddressOrigin::Static:
            return IPv6Source::Static;
        case IP::AddressOrigin::DHCP:
            return IPv6Source::DHCP;
        case IP::AddressOrigin::SLAAC:
            return IPv6Source::SLAAC;
        default:
        {
            auto originStr = sdbusplus::xyz::openbmc_project::Network::server::
                convertForMessage(origin);
            log<level::ERR>(
                "Invalid IP::AddressOrigin conversion to IPv6Source",
                entry("ORIGIN=%s", originStr.c_str()));
            elog<InternalFailure>();
        }
    }
}

/** @brief Packs the IPMI message response with IPv6 address data
 *
 *  @param[out] ret     - The IPMI response payload to be packed
 *  @param[in]  channel - The channel id corresponding to an ethernet interface
 *  @param[in]  set     - The set selector for determining address index
 *  @param[in]  origins - Set of valid origins for address filtering
 */
void getLanIPv6Address(message::Payload& ret, uint8_t channel, uint8_t set,
                       const std::unordered_set<IP::AddressOrigin>& origins)
{
    auto source = IPv6Source::Static;
    bool enabled = false;
    in6_addr addr{};
    uint8_t prefix{};
    auto status = IPv6AddressStatus::Disabled;

    auto ifaddr = channelCall<getIfAddr<AF_INET6>>(channel, set, origins);
    if (ifaddr)
    {
        source = originToSourceType(ifaddr->origin);
        enabled = (origins == originsV6Static);
        addr = ifaddr->address;
        prefix = ifaddr->prefix;
        status = IPv6AddressStatus::Active;
    }

    ret.pack(set);
    ret.pack(types::enum_cast<uint4_t>(source), uint3_t{}, enabled);
    ret.pack(std::string_view(reinterpret_cast<char*>(&addr), sizeof(addr)));
    ret.pack(prefix);
    ret.pack(types::enum_cast<uint8_t>(status));
}

/** @brief Gets the vlan ID configured on the interface
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel
 *  @return VLAN id or the standard 0 for no VLAN
 */
uint16_t getVLANProperty(sdbusplus::bus_t& bus, const ChannelParams& params)
{
    // VLAN devices will always have a separate logical object
    if (params.ifPath == params.logicalPath)
    {
        return 0;
    }

    auto vlan = std::get<uint32_t>(getDbusProperty(
        bus, params.service, params.logicalPath, INTF_VLAN, "Id"));
    if ((vlan & VLAN_VALUE_MASK) != vlan)
    {
        logWithChannel<level::ERR>(params, "networkd returned an invalid vlan",
                                   entry("VLAN=%" PRIu32, vlan));
        elog<InternalFailure>();
    }
    return vlan;
}

/** @brief Deletes all of the possible configuration parameters for a channel
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel
 */
void deconfigureChannel(sdbusplus::bus_t& bus, ChannelParams& params)
{
    // Delete all objects associated with the interface
    auto objreq = bus.new_method_call(MAPPER_BUS_NAME, MAPPER_OBJ, MAPPER_INTF,
                                      "GetSubTree");
    objreq.append(PATH_ROOT, 0, std::vector<std::string>{DELETE_INTERFACE});
    auto objreply = bus.call(objreq);
    ObjectTree objs;
    objreply.read(objs);
    for (const auto& [path, impls] : objs)
    {
        if (path.find(params.ifname) == path.npos)
        {
            continue;
        }
        for (const auto& [service, intfs] : impls)
        {
            deleteObjectIfExists(bus, service, path);
        }
        // Update params to reflect the deletion of vlan
        if (path == params.logicalPath)
        {
            params.logicalPath = params.ifPath;
        }
    }

    // Clear out any settings on the lower physical interface
    setDHCPv6Property(bus, params, EthernetInterface::DHCPConf::none, false);
}

/** @brief Creates a new VLAN on the specified interface
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel
 *  @param[in] vlan   - The id of the new vlan
 */
void createVLAN(sdbusplus::bus_t& bus, ChannelParams& params, uint16_t vlan)
{
    if (vlan == 0)
    {
        return;
    }

    auto req = bus.new_method_call(params.service.c_str(), PATH_ROOT,
                                   INTF_VLAN_CREATE, "VLAN");
    req.append(params.ifname, static_cast<uint32_t>(vlan));
    auto reply = bus.call(req);
    sdbusplus::message::object_path newPath;
    reply.read(newPath);
    params.logicalPath = std::move(newPath);
}

/** @brief Performs the necessary reconfiguration to change the VLAN
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel
 *  @param[in] vlan   - The new vlan id to use
 */
void reconfigureVLAN(sdbusplus::bus_t& bus, ChannelParams& params,
                     uint16_t vlan)
{
    // Unfortunatetly we don't have built-in functions to migrate our interface
    // customizations to new VLAN interfaces, or have some kind of decoupling.
    // We therefore must retain all of our old information, setup the new VLAN
    // configuration, then restore the old info.

    // Save info from the old logical interface
    ObjectLookupCache ips(bus, params, INTF_IP);
    auto ifaddr4 = findIfAddr<AF_INET>(bus, params, 0, originsV4, ips);
    std::vector<IfAddr<AF_INET6>> ifaddrs6;
    for (uint8_t i = 0; i < MAX_IPV6_STATIC_ADDRESSES; ++i)
    {
        auto ifaddr6 =
            findIfAddr<AF_INET6>(bus, params, i, originsV6Static, ips);
        if (!ifaddr6)
        {
            break;
        }
        ifaddrs6.push_back(std::move(*ifaddr6));
    }
    EthernetInterface::DHCPConf dhcp = getDHCPProperty(bus, params);
    ObjectLookupCache neighbors(bus, params, INTF_NEIGHBOR);
    auto neighbor4 = findGatewayNeighbor<AF_INET>(bus, params, neighbors);
    auto neighbor6 = findGatewayNeighbor<AF_INET6>(bus, params, neighbors);

    deconfigureChannel(bus, params);
    createVLAN(bus, params, vlan);

    // Re-establish the saved settings
    setDHCPv6Property(bus, params, dhcp, false);
    if (ifaddr4)
    {
        createIfAddr<AF_INET>(bus, params, ifaddr4->address, ifaddr4->prefix);
    }
    for (const auto& ifaddr6 : ifaddrs6)
    {
        createIfAddr<AF_INET6>(bus, params, ifaddr6.address, ifaddr6.prefix);
    }
    if (neighbor4)
    {
        createNeighbor<AF_INET>(bus, params, neighbor4->ip, neighbor4->mac);
    }
    if (neighbor6)
    {
        createNeighbor<AF_INET6>(bus, params, neighbor6->ip, neighbor6->mac);
    }
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
        log<level::ERR>("Invalid prefix", entry("PREFIX=%" PRIu8, prefix));
        elog<InternalFailure>();
    }
    if (prefix == 0)
    {
        // Avoids 32-bit lshift by 32 UB
        return {};
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
        char maskStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &netmask, maskStr, sizeof(maskStr));
        log<level::ERR>("Invalid netmask", entry("NETMASK=%s", maskStr));
        elog<InternalFailure>();
    }
    return static_cast<bool>(x)
               ? AddrFamily<AF_INET>::defaultPrefix - __builtin_ctz(x)
               : 0;
}

// We need to store this value so it can be returned to the client
// It is volatile so safe to store in daemon memory.
static std::unordered_map<uint8_t, SetStatus> setStatus;

// Until we have good support for fixed versions of IPMI tool
// we need to return the VLAN id for disabled VLANs. The value is only
// used for verification that a disable operation succeeded and will only
// be sent if our system indicates that vlans are disabled.
static std::unordered_map<uint8_t, uint16_t> lastDisabledVlan;

/** @brief Gets the set status for the channel if it exists
 *         Otherise populates and returns the default value.
 *
 *  @param[in] channel - The channel id corresponding to an ethernet interface
 *  @return A reference to the SetStatus for the channel
 */
SetStatus& getSetStatus(uint8_t channel)
{
    auto it = setStatus.find(channel);
    if (it != setStatus.end())
    {
        return it->second;
    }
    return setStatus[channel] = SetStatus::Complete;
}

/** @brief Gets the IPv6 Router Advertisement value
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel
 *  @return networkd IPV6AcceptRA value
 */
static bool getIPv6AcceptRA(sdbusplus::bus_t& bus, const ChannelParams& params)
{
    auto raEnabled =
        std::get<bool>(getDbusProperty(bus, params.service, params.logicalPath,
                                       INTF_ETHERNET, "IPv6AcceptRA"));
    return raEnabled;
}

/** @brief Sets the IPv6AcceptRA flag
 *
 *  @param[in] bus           - The bus object used for lookups
 *  @param[in] params        - The parameters for the channel
 *  @param[in] ipv6AcceptRA  - boolean to enable/disable IPv6 Routing
 *                             Advertisement
 */
void setIPv6AcceptRA(sdbusplus::bus_t& bus, const ChannelParams& params,
                     const bool ipv6AcceptRA)
{
    setDbusProperty(bus, params.service, params.logicalPath, INTF_ETHERNET,
                    "IPv6AcceptRA", ipv6AcceptRA);
}

/**
 * Define placeholder command handlers for the OEM Extension bytes for the Set
 * LAN Configuration Parameters and Get LAN Configuration Parameters
 * commands. Using "weak" linking allows the placeholder setLanOem/getLanOem
 * functions below to be overridden.
 * To create handlers for your own proprietary command set:
 *   Create/modify a phosphor-ipmi-host Bitbake append file within your Yocto
 *   recipe
 *   Create C++ file(s) that define IPMI handler functions matching the
 *     function names below (i.e. setLanOem). The default name for the
 *     transport IPMI commands is transporthandler_oem.cpp.
 *   Add:
 *      EXTRA_OEMESON:append = "-Dtransport-oem=enabled"
 *   Create a do_configure:prepend()/do_install:append() method in your
 *   bbappend file to copy the file to the build directory.
 *   Add:
 *   PROJECT_SRC_DIR := "${THISDIR}/${PN}"
 *   # Copy the "strong" functions into the working directory, overriding the
 *   # placeholder functions.
 *   do_configure:prepend(){
 *      cp -f ${PROJECT_SRC_DIR}/transporthandler_oem.cpp ${S}
 *   }
 *
 *   # Clean up after complilation has completed
 *   do_install:append(){
 *      rm -f ${S}/transporthandler_oem.cpp
 *   }
 *
 */

/**
 * Define the placeholder OEM commands as having weak linkage. Create
 * setLanOem, and getLanOem functions in the transporthandler_oem.cpp
 * file. The functions defined there must not have the "weak" attribute
 * applied to them.
 */
RspType<> setLanOem(uint8_t channel, uint8_t parameter, message::Payload& req)
    __attribute__((weak));
RspType<message::Payload> getLanOem(uint8_t channel, uint8_t parameter,
                                    uint8_t set, uint8_t block)
    __attribute__((weak));

RspType<> setLanOem(uint8_t, uint8_t, message::Payload& req)
{
    req.trailingOk = true;
    return response(ccParamNotSupported);
}

RspType<message::Payload> getLanOem(uint8_t, uint8_t, uint8_t, uint8_t)
{
    return response(ccParamNotSupported);
}
/**
 * @brief is MAC address valid.
 *
 * This function checks whether the MAC address is valid or not.
 *
 * @param[in] mac - MAC address.
 * @return true if MAC address is valid else retun false.
 **/
bool isValidMACAddress(const ether_addr& mac)
{
    // check if mac address is empty
    if (equal(mac, ether_addr{}))
    {
        return false;
    }
    // we accept only unicast MAC addresses and  same thing has been checked in
    // phosphor-network layer. If the least significant bit of the first octet
    // is set to 1, it is multicast MAC else it is unicast MAC address.
    if (mac.ether_addr_octet[0] & 1)
    {
        return false;
    }
    return true;
}

RspType<> setLan(Context::ptr ctx, uint4_t channelBits, uint4_t reserved1,
                 uint8_t parameter, message::Payload& req)
{
    const uint8_t channel = convertCurrentChannelNum(
        static_cast<uint8_t>(channelBits), ctx->channel);
    if (reserved1 || !isValidChannel(channel))
    {
        log<level::ERR>("Set Lan - Invalid field in request");
        req.trailingOk = true;
        return responseInvalidFieldRequest();
    }

    switch (static_cast<LanParam>(parameter))
    {
        case LanParam::SetStatus:
        {
            uint2_t flag;
            uint6_t rsvd;
            if (req.unpack(flag, rsvd) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }
            if (rsvd)
            {
                return responseInvalidFieldRequest();
            }
            auto status = static_cast<SetStatus>(static_cast<uint8_t>(flag));
            switch (status)
            {
                case SetStatus::Complete:
                {
                    getSetStatus(channel) = status;
                    return responseSuccess();
                }
                case SetStatus::InProgress:
                {
                    auto& storedStatus = getSetStatus(channel);
                    if (storedStatus == SetStatus::InProgress)
                    {
                        return response(ccParamSetLocked);
                    }
                    storedStatus = status;
                    return responseSuccess();
                }
                case SetStatus::Commit:
                    if (getSetStatus(channel) != SetStatus::InProgress)
                    {
                        return responseInvalidFieldRequest();
                    }
                    return responseSuccess();
            }
            return response(ccParamNotSupported);
        }
        case LanParam::AuthSupport:
        {
            req.trailingOk = true;
            return response(ccParamReadOnly);
        }
        case LanParam::AuthEnables:
        {
            req.trailingOk = true;
            return response(ccParamReadOnly);
        }
        case LanParam::IP:
        {
            EthernetInterface::DHCPConf dhcp =
                channelCall<getDHCPProperty>(channel);
            if ((dhcp == EthernetInterface::DHCPConf::v4) ||
                (dhcp == EthernetInterface::DHCPConf::both))
            {
                return responseCommandNotAvailable();
            }
            in_addr ip;
            std::array<uint8_t, sizeof(ip)> bytes;
            if (req.unpack(bytes) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }
            copyInto(ip, bytes);
            channelCall<reconfigureIfAddr4>(channel, ip, std::nullopt);
            return responseSuccess();
        }
        case LanParam::IPSrc:
        {
            uint4_t flag;
            uint4_t rsvd;
            if (req.unpack(flag, rsvd) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }
            if (rsvd)
            {
                return responseInvalidFieldRequest();
            }
            switch (static_cast<IPSrc>(static_cast<uint8_t>(flag)))
            {
                case IPSrc::DHCP:
                {
                    // The IPSrc IPMI command is only for IPv4
                    // management. Modifying IPv6 state is done using
                    // a completely different Set LAN Configuration
                    // subcommand.
                    channelCall<setDHCPv4Property>(
                        channel, EthernetInterface::DHCPConf::v4);
                    return responseSuccess();
                }
                case IPSrc::Unspecified:
                case IPSrc::Static:
                {
                    channelCall<setDHCPv4Property>(
                        channel, EthernetInterface::DHCPConf::none);
                    return responseSuccess();
                }
                case IPSrc::BIOS:
                case IPSrc::BMC:
                {
                    return responseInvalidFieldRequest();
                }
            }
            return response(ccParamNotSupported);
        }
        case LanParam::MAC:
        {
            ether_addr mac;
            std::array<uint8_t, sizeof(mac)> bytes;
            if (req.unpack(bytes) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }
            copyInto(mac, bytes);

            if (!isValidMACAddress(mac))
            {
                return responseInvalidFieldRequest();
            }
            channelCall<setMACProperty>(channel, mac);
            return responseSuccess();
        }
        case LanParam::SubnetMask:
        {
            EthernetInterface::DHCPConf dhcp =
                channelCall<getDHCPProperty>(channel);
            if ((dhcp == EthernetInterface::DHCPConf::v4) ||
                (dhcp == EthernetInterface::DHCPConf::both))
            {
                return responseCommandNotAvailable();
            }
            in_addr netmask;
            std::array<uint8_t, sizeof(netmask)> bytes;
            if (req.unpack(bytes) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }
            copyInto(netmask, bytes);
            uint8_t prefix = netmaskToPrefix(netmask);
            if (prefix < MIN_IPV4_PREFIX_LENGTH)
            {
                return responseInvalidFieldRequest();
            }
            channelCall<reconfigureIfAddr4>(channel, std::nullopt, prefix);
            return responseSuccess();
        }
        case LanParam::Gateway1:
        {
            EthernetInterface::DHCPConf dhcp =
                channelCall<getDHCPProperty>(channel);
            if ((dhcp == EthernetInterface::DHCPConf::v4) ||
                (dhcp == EthernetInterface::DHCPConf::both))
            {
                return responseCommandNotAvailable();
            }
            in_addr gateway;
            std::array<uint8_t, sizeof(gateway)> bytes;
            if (req.unpack(bytes) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }
            copyInto(gateway, bytes);
            channelCall<setGatewayProperty<AF_INET>>(channel, gateway);
            return responseSuccess();
        }
        case LanParam::Gateway1MAC:
        {
            ether_addr gatewayMAC;
            std::array<uint8_t, sizeof(gatewayMAC)> bytes;
            if (req.unpack(bytes) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }
            copyInto(gatewayMAC, bytes);
            channelCall<reconfigureGatewayMAC<AF_INET>>(channel, gatewayMAC);
            return responseSuccess();
        }
        case LanParam::VLANId:
        {
            uint12_t vlanData = 0;
            uint3_t reserved = 0;
            bool vlanEnable = 0;

            if (req.unpack(vlanData) || req.unpack(reserved) ||
                req.unpack(vlanEnable) || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }

            if (reserved)
            {
                return responseInvalidFieldRequest();
            }

            uint16_t vlan = static_cast<uint16_t>(vlanData);

            if (!vlanEnable)
            {
                lastDisabledVlan[channel] = vlan;
                vlan = 0;
            }
            else if (vlan == 0 || vlan == VLAN_VALUE_MASK)
            {
                return responseInvalidFieldRequest();
            }

            channelCall<reconfigureVLAN>(channel, vlan);
            return responseSuccess();
        }
        case LanParam::CiphersuiteSupport:
        case LanParam::CiphersuiteEntries:
        case LanParam::IPFamilySupport:
        {
            req.trailingOk = true;
            return response(ccParamReadOnly);
        }
        case LanParam::IPFamilyEnables:
        {
            uint8_t enables;
            if (req.unpack(enables) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }
            switch (static_cast<IPFamilyEnables>(enables))
            {
                case IPFamilyEnables::DualStack:
                    return responseSuccess();
                case IPFamilyEnables::IPv4Only:
                case IPFamilyEnables::IPv6Only:
                    return response(ccParamNotSupported);
            }
            return response(ccParamNotSupported);
        }
        case LanParam::IPv6Status:
        {
            req.trailingOk = true;
            return response(ccParamReadOnly);
        }
        case LanParam::IPv6StaticAddresses:
        {
            uint8_t set;
            uint7_t rsvd;
            bool enabled;
            in6_addr ip;
            std::array<uint8_t, sizeof(ip)> ipbytes;
            uint8_t prefix;
            uint8_t status;
            if (req.unpack(set, rsvd, enabled, ipbytes, prefix, status) != 0 ||
                !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }
            if (rsvd)
            {
                return responseInvalidFieldRequest();
            }
            copyInto(ip, ipbytes);
            if (enabled)
            {
                if (prefix < MIN_IPV6_PREFIX_LENGTH ||
                    prefix > MAX_IPV6_PREFIX_LENGTH)
                {
                    return responseParmOutOfRange();
                }
                try
                {
                    channelCall<reconfigureIfAddr6>(channel, set, ip, prefix);
                }
                catch (const sdbusplus::exception_t& e)
                {
                    if (std::string_view err{
                            "xyz.openbmc_project.Common.Error.InvalidArgument"};
                        err == e.name())
                    {
                        return responseInvalidFieldRequest();
                    }
                    else
                    {
                        throw;
                    }
                }
            }
            else
            {
                channelCall<deconfigureIfAddr6>(channel, set);
            }
            return responseSuccess();
        }
        case LanParam::IPv6DynamicAddresses:
        {
            req.trailingOk = true;
            return response(ccParamReadOnly);
        }
        case LanParam::IPv6RouterControl:
        {
            std::bitset<8> control;
            constexpr uint8_t reservedRACCBits = 0xfc;
            if (req.unpack(control) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }
            if (std::bitset<8> expected(control &
                                        std::bitset<8>(reservedRACCBits));
                expected.any())
            {
                return response(ccParamNotSupported);
            }

            bool enableRA = control[IPv6RouterControlFlag::Dynamic];
            channelCall<setIPv6AcceptRA>(channel, enableRA);
            return responseSuccess();
        }
        case LanParam::IPv6StaticRouter1IP:
        {
            in6_addr gateway;
            std::array<uint8_t, sizeof(gateway)> bytes;
            if (req.unpack(bytes) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }
            copyInto(gateway, bytes);
            channelCall<setGatewayProperty<AF_INET6>>(channel, gateway);
            return responseSuccess();
        }
        case LanParam::IPv6StaticRouter1MAC:
        {
            ether_addr mac;
            std::array<uint8_t, sizeof(mac)> bytes;
            if (req.unpack(bytes) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }
            copyInto(mac, bytes);
            channelCall<reconfigureGatewayMAC<AF_INET6>>(channel, mac);
            return responseSuccess();
        }
        case LanParam::IPv6StaticRouter1PrefixLength:
        {
            uint8_t prefix;
            if (req.unpack(prefix) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }
            if (prefix != 0)
            {
                return responseInvalidFieldRequest();
            }
            return responseSuccess();
        }
        case LanParam::IPv6StaticRouter1PrefixValue:
        {
            std::array<uint8_t, sizeof(in6_addr)> bytes;
            if (req.unpack(bytes) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }
            // Accept any prefix value since our prefix length has to be 0
            return responseSuccess();
        }
        case LanParam::cipherSuitePrivilegeLevels:
        {
            uint8_t reserved;
            std::array<uint4_t, ipmi::maxCSRecords> cipherSuitePrivs;

            if (req.unpack(reserved, cipherSuitePrivs) || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }

            if (reserved)
            {
                return responseInvalidFieldRequest();
            }

            uint8_t resp =
                getCipherConfigObject(csPrivFileName, csPrivDefaultFileName)
                    .setCSPrivilegeLevels(channel, cipherSuitePrivs);
            if (!resp)
            {
                return responseSuccess();
            }
            else
            {
                req.trailingOk = true;
                return response(resp);
            }
        }
    }

    if ((parameter >= oemCmdStart) && (parameter <= oemCmdEnd))
    {
        return setLanOem(channel, parameter, req);
    }

    req.trailingOk = true;
    return response(ccParamNotSupported);
}

RspType<message::Payload> getLan(Context::ptr ctx, uint4_t channelBits,
                                 uint3_t reserved, bool revOnly,
                                 uint8_t parameter, uint8_t set, uint8_t block)
{
    message::Payload ret;
    constexpr uint8_t current_revision = 0x11;
    ret.pack(current_revision);

    if (revOnly)
    {
        return responseSuccess(std::move(ret));
    }

    const uint8_t channel = convertCurrentChannelNum(
        static_cast<uint8_t>(channelBits), ctx->channel);
    if (reserved || !isValidChannel(channel))
    {
        log<level::ERR>("Get Lan - Invalid field in request");
        return responseInvalidFieldRequest();
    }

    static std::vector<uint8_t> cipherList;
    static bool listInit = false;
    if (!listInit)
    {
        try
        {
            cipherList = cipher::getCipherList();
            listInit = true;
        }
        catch (const std::exception& e)
        {
        }
    }

    switch (static_cast<LanParam>(parameter))
    {
        case LanParam::SetStatus:
        {
            SetStatus status;
            try
            {
                status = setStatus.at(channel);
            }
            catch (const std::out_of_range&)
            {
                status = SetStatus::Complete;
            }
            ret.pack(types::enum_cast<uint2_t>(status), uint6_t{});
            return responseSuccess(std::move(ret));
        }
        case LanParam::AuthSupport:
        {
            std::bitset<6> support;
            ret.pack(support, uint2_t{});
            return responseSuccess(std::move(ret));
        }
        case LanParam::AuthEnables:
        {
            std::bitset<6> enables;
            ret.pack(enables, uint2_t{}); // Callback
            ret.pack(enables, uint2_t{}); // User
            ret.pack(enables, uint2_t{}); // Operator
            ret.pack(enables, uint2_t{}); // Admin
            ret.pack(enables, uint2_t{}); // OEM
            return responseSuccess(std::move(ret));
        }
        case LanParam::IP:
        {
            auto ifaddr = channelCall<getIfAddr4>(channel);
            in_addr addr{};
            if (ifaddr)
            {
                addr = ifaddr->address;
            }
            ret.pack(dataRef(addr));
            return responseSuccess(std::move(ret));
        }
        case LanParam::IPSrc:
        {
            auto src = IPSrc::Static;
            EthernetInterface::DHCPConf dhcp =
                channelCall<getDHCPProperty>(channel);
            if ((dhcp == EthernetInterface::DHCPConf::v4) ||
                (dhcp == EthernetInterface::DHCPConf::both))
            {
                src = IPSrc::DHCP;
            }
            ret.pack(types::enum_cast<uint4_t>(src), uint4_t{});
            return responseSuccess(std::move(ret));
        }
        case LanParam::MAC:
        {
            ether_addr mac = channelCall<getMACProperty>(channel);
            ret.pack(dataRef(mac));
            return responseSuccess(std::move(ret));
        }
        case LanParam::SubnetMask:
        {
            auto ifaddr = channelCall<getIfAddr4>(channel);
            uint8_t prefix = AddrFamily<AF_INET>::defaultPrefix;
            if (ifaddr)
            {
                prefix = ifaddr->prefix;
            }
            in_addr netmask = prefixToNetmask(prefix);
            ret.pack(dataRef(netmask));
            return responseSuccess(std::move(ret));
        }
        case LanParam::Gateway1:
        {
            auto gateway =
                channelCall<getGatewayProperty<AF_INET>>(channel).value_or(
                    in_addr{});
            ret.pack(dataRef(gateway));
            return responseSuccess(std::move(ret));
        }
        case LanParam::Gateway1MAC:
        {
            ether_addr mac{};
            auto neighbor = channelCall<getGatewayNeighbor<AF_INET>>(channel);
            if (neighbor)
            {
                mac = neighbor->mac;
            }
            ret.pack(dataRef(mac));
            return responseSuccess(std::move(ret));
        }
        case LanParam::VLANId:
        {
            uint16_t vlan = channelCall<getVLANProperty>(channel);
            if (vlan != 0)
            {
                vlan |= VLAN_ENABLE_FLAG;
            }
            else
            {
                vlan = lastDisabledVlan[channel];
            }
            ret.pack(vlan);
            return responseSuccess(std::move(ret));
        }
        case LanParam::CiphersuiteSupport:
        {
            if (getChannelSessionSupport(channel) ==
                EChannelSessSupported::none)
            {
                return responseInvalidFieldRequest();
            }
            if (!listInit)
            {
                return responseUnspecifiedError();
            }
            ret.pack(static_cast<uint8_t>(cipherList.size() - 1));
            return responseSuccess(std::move(ret));
        }
        case LanParam::CiphersuiteEntries:
        {
            if (getChannelSessionSupport(channel) ==
                EChannelSessSupported::none)
            {
                return responseInvalidFieldRequest();
            }
            if (!listInit)
            {
                return responseUnspecifiedError();
            }
            ret.pack(cipherList);
            return responseSuccess(std::move(ret));
        }
        case LanParam::IPFamilySupport:
        {
            std::bitset<8> support;
            support[IPFamilySupportFlag::IPv6Only] = 0;
            support[IPFamilySupportFlag::DualStack] = 1;
            support[IPFamilySupportFlag::IPv6Alerts] = 1;
            ret.pack(support);
            return responseSuccess(std::move(ret));
        }
        case LanParam::IPFamilyEnables:
        {
            ret.pack(static_cast<uint8_t>(IPFamilyEnables::DualStack));
            return responseSuccess(std::move(ret));
        }
        case LanParam::IPv6Status:
        {
            ret.pack(MAX_IPV6_STATIC_ADDRESSES);
            ret.pack(MAX_IPV6_DYNAMIC_ADDRESSES);
            std::bitset<8> support;
            support[IPv6StatusFlag::DHCP] = 1;
            support[IPv6StatusFlag::SLAAC] = 1;
            ret.pack(support);
            return responseSuccess(std::move(ret));
        }
        case LanParam::IPv6StaticAddresses:
        {
            if (set >= MAX_IPV6_STATIC_ADDRESSES)
            {
                return responseParmOutOfRange();
            }
            getLanIPv6Address(ret, channel, set, originsV6Static);
            return responseSuccess(std::move(ret));
        }
        case LanParam::IPv6DynamicAddresses:
        {
            if (set >= MAX_IPV6_DYNAMIC_ADDRESSES)
            {
                return responseParmOutOfRange();
            }
            getLanIPv6Address(ret, channel, set, originsV6Dynamic);
            return responseSuccess(std::move(ret));
        }
        case LanParam::IPv6RouterControl:
        {
            std::bitset<8> control;
            control[IPv6RouterControlFlag::Dynamic] =
                channelCall<getIPv6AcceptRA>(channel);
            control[IPv6RouterControlFlag::Static] = 1;
            ret.pack(control);
            return responseSuccess(std::move(ret));
        }
        case LanParam::IPv6StaticRouter1IP:
        {
            in6_addr gateway{};
            EthernetInterface::DHCPConf dhcp =
                channelCall<getDHCPProperty>(channel);
            if ((dhcp == EthernetInterface::DHCPConf::v4) ||
                (dhcp == EthernetInterface::DHCPConf::none))
            {
                gateway =
                    channelCall<getGatewayProperty<AF_INET6>>(channel).value_or(
                        in6_addr{});
            }
            ret.pack(dataRef(gateway));
            return responseSuccess(std::move(ret));
        }
        case LanParam::IPv6StaticRouter1MAC:
        {
            ether_addr mac{};
            auto neighbor = channelCall<getGatewayNeighbor<AF_INET6>>(channel);
            if (neighbor)
            {
                mac = neighbor->mac;
            }
            ret.pack(dataRef(mac));
            return responseSuccess(std::move(ret));
        }
        case LanParam::IPv6StaticRouter1PrefixLength:
        {
            ret.pack(UINT8_C(0));
            return responseSuccess(std::move(ret));
        }
        case LanParam::IPv6StaticRouter1PrefixValue:
        {
            in6_addr prefix{};
            ret.pack(dataRef(prefix));
            return responseSuccess(std::move(ret));
        }
        case LanParam::cipherSuitePrivilegeLevels:
        {
            std::array<uint4_t, ipmi::maxCSRecords> csPrivilegeLevels;

            uint8_t resp =
                getCipherConfigObject(csPrivFileName, csPrivDefaultFileName)
                    .getCSPrivilegeLevels(channel, csPrivilegeLevels);
            if (!resp)
            {
                constexpr uint8_t reserved1 = 0x00;
                ret.pack(reserved1, csPrivilegeLevels);
                return responseSuccess(std::move(ret));
            }
            else
            {
                return response(resp);
            }
        }
    }

    if ((parameter >= oemCmdStart) && (parameter <= oemCmdEnd))
    {
        return getLanOem(channel, parameter, set, block);
    }

    return response(ccParamNotSupported);
}

constexpr const char* solInterface = "xyz.openbmc_project.Ipmi.SOL";
constexpr const char* solPath = "/xyz/openbmc_project/ipmi/sol/";
constexpr const uint16_t solDefaultPort = 623;

RspType<> setSolConfParams(Context::ptr ctx, uint4_t channelBits,
                           uint4_t /*reserved*/, uint8_t parameter,
                           message::Payload& req)
{
    const uint8_t channel = convertCurrentChannelNum(
        static_cast<uint8_t>(channelBits), ctx->channel);

    if (!isValidChannel(channel))
    {
        log<level::ERR>("Set Sol Config - Invalid channel in request");
        return responseInvalidFieldRequest();
    }

    std::string solService{};
    std::string solPathWitheEthName = solPath + ipmi::getChannelName(channel);

    if (ipmi::getService(ctx, solInterface, solPathWitheEthName, solService))
    {
        log<level::ERR>("Set Sol Config - Invalid solInterface",
                        entry("SERVICE=%s", solService.c_str()),
                        entry("OBJPATH=%s", solPathWitheEthName.c_str()),
                        entry("INTERFACE=%s", solInterface));
        return responseInvalidFieldRequest();
    }

    switch (static_cast<SolConfParam>(parameter))
    {
        case SolConfParam::Progress:
        {
            uint8_t progress;
            if (req.unpack(progress) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }

            if (ipmi::setDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "Progress", progress))
            {
                return responseUnspecifiedError();
            }
            break;
        }
        case SolConfParam::Enable:
        {
            bool enable;
            uint7_t reserved2;

            if (req.unpack(enable, reserved2) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }

            if (ipmi::setDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "Enable", enable))
            {
                return responseUnspecifiedError();
            }
            break;
        }
        case SolConfParam::Authentication:
        {
            uint4_t privilegeBits{};
            uint2_t reserved2{};
            bool forceAuth = false;
            bool forceEncrypt = false;

            if (req.unpack(privilegeBits, reserved2, forceAuth, forceEncrypt) !=
                    0 ||
                !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }

            uint8_t privilege = static_cast<uint8_t>(privilegeBits);
            if (privilege < static_cast<uint8_t>(Privilege::None) ||
                privilege > static_cast<uint8_t>(Privilege::Oem))
            {
                return ipmi::responseInvalidFieldRequest();
            }

            if (ipmi::setDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "Privilege", privilege))
            {
                return responseUnspecifiedError();
            }

            if (ipmi::setDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "ForceEncryption",
                                      forceEncrypt))
            {
                return responseUnspecifiedError();
            }

            if (ipmi::setDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "ForceAuthentication",
                                      forceAuth))
            {
                return responseUnspecifiedError();
            }
            break;
        }
        case SolConfParam::Accumulate:
        {
            uint8_t interval;
            uint8_t threshold;
            if (req.unpack(interval, threshold) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }

            if (threshold == 0)
            {
                return responseInvalidFieldRequest();
            }

            if (ipmi::setDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "AccumulateIntervalMS",
                                      interval))
            {
                return responseUnspecifiedError();
            }

            if (ipmi::setDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "Threshold", threshold))
            {
                return responseUnspecifiedError();
            }
            break;
        }
        case SolConfParam::Retry:
        {
            uint3_t countBits;
            uint5_t reserved2;
            uint8_t interval;

            if (req.unpack(countBits, reserved2, interval) != 0 ||
                !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }

            uint8_t count = static_cast<uint8_t>(countBits);
            if (ipmi::setDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "RetryCount", count))
            {
                return responseUnspecifiedError();
            }

            if (ipmi::setDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "RetryIntervalMS",
                                      interval))
            {
                return responseUnspecifiedError();
            }
            break;
        }
        case SolConfParam::Port:
        {
            return response(ipmiCCWriteReadParameter);
        }
        case SolConfParam::NonVbitrate:
        case SolConfParam::Vbitrate:
        case SolConfParam::Channel:
        default:
            return response(ipmiCCParamNotSupported);
    }
    return responseSuccess();
}

RspType<message::Payload> getSolConfParams(Context::ptr ctx,
                                           uint4_t channelBits,
                                           uint3_t /*reserved*/, bool revOnly,
                                           uint8_t parameter, uint8_t /*set*/,
                                           uint8_t /*block*/)
{
    message::Payload ret;
    constexpr uint8_t current_revision = 0x11;
    ret.pack(current_revision);
    if (revOnly)
    {
        return responseSuccess(std::move(ret));
    }

    const uint8_t channel = convertCurrentChannelNum(
        static_cast<uint8_t>(channelBits), ctx->channel);

    if (!isValidChannel(channel))
    {
        log<level::ERR>("Get Sol Config - Invalid channel in request");
        return responseInvalidFieldRequest();
    }

    std::string solService{};
    std::string solPathWitheEthName = solPath + ipmi::getChannelName(channel);

    if (ipmi::getService(ctx, solInterface, solPathWitheEthName, solService))
    {
        log<level::ERR>("Set Sol Config - Invalid solInterface",
                        entry("SERVICE=%s", solService.c_str()),
                        entry("OBJPATH=%s", solPathWitheEthName.c_str()),
                        entry("INTERFACE=%s", solInterface));
        return responseInvalidFieldRequest();
    }

    switch (static_cast<SolConfParam>(parameter))
    {
        case SolConfParam::Progress:
        {
            uint8_t progress;
            if (ipmi::getDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "Progress", progress))
            {
                return responseUnspecifiedError();
            }
            ret.pack(progress);
            return responseSuccess(std::move(ret));
        }
        case SolConfParam::Enable:
        {
            bool enable{};
            if (ipmi::getDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "Enable", enable))
            {
                return responseUnspecifiedError();
            }
            ret.pack(enable, uint7_t{});
            return responseSuccess(std::move(ret));
        }
        case SolConfParam::Authentication:
        {
            // 4bits, cast when pack
            uint8_t privilege;
            bool forceAuth = false;
            bool forceEncrypt = false;

            if (ipmi::getDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "Privilege", privilege))
            {
                return responseUnspecifiedError();
            }

            if (ipmi::getDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "ForceAuthentication",
                                      forceAuth))
            {
                return responseUnspecifiedError();
            }

            if (ipmi::getDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "ForceEncryption",
                                      forceEncrypt))
            {
                return responseUnspecifiedError();
            }
            ret.pack(uint4_t{privilege}, uint2_t{}, forceAuth, forceEncrypt);
            return responseSuccess(std::move(ret));
        }
        case SolConfParam::Accumulate:
        {
            uint8_t interval{}, threshold{};

            if (ipmi::getDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "AccumulateIntervalMS",
                                      interval))
            {
                return responseUnspecifiedError();
            }

            if (ipmi::getDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "Threshold", threshold))
            {
                return responseUnspecifiedError();
            }
            ret.pack(interval, threshold);
            return responseSuccess(std::move(ret));
        }
        case SolConfParam::Retry:
        {
            // 3bits, cast when cast
            uint8_t count{};
            uint8_t interval{};

            if (ipmi::getDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "RetryCount", count))
            {
                return responseUnspecifiedError();
            }

            if (ipmi::getDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "RetryIntervalMS",
                                      interval))
            {
                return responseUnspecifiedError();
            }
            ret.pack(uint3_t{count}, uint5_t{}, interval);
            return responseSuccess(std::move(ret));
        }
        case SolConfParam::Port:
        {
            auto port = solDefaultPort;
            ret.pack(static_cast<uint16_t>(port));
            return responseSuccess(std::move(ret));
        }
        case SolConfParam::Channel:
        {
            ret.pack(channel);
            return responseSuccess(std::move(ret));
        }
        case SolConfParam::NonVbitrate:
        case SolConfParam::Vbitrate:
        default:
            return response(ipmiCCParamNotSupported);
    }

    return response(ccParamNotSupported);
}

} // namespace transport
} // namespace ipmi

void register_netfn_transport_functions() __attribute__((constructor));

void register_netfn_transport_functions()
{
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnTransport,
                          ipmi::transport::cmdSetLanConfigParameters,
                          ipmi::Privilege::Admin, ipmi::transport::setLan);
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnTransport,
                          ipmi::transport::cmdGetLanConfigParameters,
                          ipmi::Privilege::Operator, ipmi::transport::getLan);
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnTransport,
                          ipmi::transport::cmdSetSolConfigParameters,
                          ipmi::Privilege::Admin,
                          ipmi::transport::setSolConfParams);
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnTransport,
                          ipmi::transport::cmdGetSolConfigParameters,
                          ipmi::Privilege::User,
                          ipmi::transport::getSolConfParams);
}
