#pragma once

#include "app/channel.hpp"
#include "user_channel/cipher_mgmt.hpp"

#include <arpa/inet.h>
#include <netinet/ether.h>

#include <array>
#include <bitset>
#include <cinttypes>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <functional>
#include <ipmid/api-types.hpp>
#include <ipmid/api.hpp>
#include <ipmid/message.hpp>
#include <ipmid/message/types.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <optional>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/exception.hpp>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <user_channel/channel_layer.hpp>
#include <utility>
#include <vector>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/Network/EthernetInterface/server.hpp>
#include <xyz/openbmc_project/Network/IP/server.hpp>
#include <xyz/openbmc_project/Network/Neighbor/server.hpp>

namespace ipmi
{
namespace transport
{

// D-Bus Network Daemon definitions
constexpr auto PATH_ROOT = "/xyz/openbmc_project/network";
constexpr auto INTF_ETHERNET = "xyz.openbmc_project.Network.EthernetInterface";
constexpr auto INTF_IP = "xyz.openbmc_project.Network.IP";
constexpr auto INTF_IP_CREATE = "xyz.openbmc_project.Network.IP.Create";
constexpr auto INTF_MAC = "xyz.openbmc_project.Network.MACAddress";
constexpr auto INTF_NEIGHBOR = "xyz.openbmc_project.Network.Neighbor";
constexpr auto INTF_NEIGHBOR_CREATE_STATIC =
    "xyz.openbmc_project.Network.Neighbor.CreateStatic";
constexpr auto INTF_VLAN = "xyz.openbmc_project.Network.VLAN";
constexpr auto INTF_VLAN_CREATE = "xyz.openbmc_project.Network.VLAN.Create";

/** @brief IPMI LAN Parameters */
enum class LanParam : uint8_t
{
    SetStatus = 0,
    AuthSupport = 1,
    AuthEnables = 2,
    IP = 3,
    IPSrc = 4,
    MAC = 5,
    SubnetMask = 6,
    Gateway1 = 12,
    Gateway1MAC = 13,
    VLANId = 20,
    CiphersuiteSupport = 22,
    CiphersuiteEntries = 23,
    cipherSuitePrivilegeLevels = 24,
    IPFamilySupport = 50,
    IPFamilyEnables = 51,
    IPv6Status = 55,
    IPv6StaticAddresses = 56,
    IPv6DynamicAddresses = 59,
    IPv6RouterControl = 64,
    IPv6StaticRouter1IP = 65,
    IPv6StaticRouter1MAC = 66,
    IPv6StaticRouter1PrefixLength = 67,
    IPv6StaticRouter1PrefixValue = 68,
};

/** @brief IPMI IP Origin Types */
enum class IPSrc : uint8_t
{
    Unspecified = 0,
    Static = 1,
    DHCP = 2,
    BIOS = 3,
    BMC = 4,
};

/** @brief IPMI Set Status */
enum class SetStatus : uint8_t
{
    Complete = 0,
    InProgress = 1,
    Commit = 2,
};

/** @brief IPMI Family Suport Bits */
namespace IPFamilySupportFlag
{
constexpr uint8_t IPv6Only = 0;
constexpr uint8_t DualStack = 1;
constexpr uint8_t IPv6Alerts = 2;
} // namespace IPFamilySupportFlag

/** @brief IPMI IPFamily Enables Flag */
enum class IPFamilyEnables : uint8_t
{
    IPv4Only = 0,
    IPv6Only = 1,
    DualStack = 2,
};

/** @brief IPMI IPv6 Dyanmic Status Bits */
namespace IPv6StatusFlag
{
constexpr uint8_t DHCP = 0;
constexpr uint8_t SLAAC = 1;
}; // namespace IPv6StatusFlag

/** @brief IPMI IPv6 Source */
enum class IPv6Source : uint8_t
{
    Static = 0,
    SLAAC = 1,
    DHCP = 2,
};

/** @brief IPMI IPv6 Address Status */
enum class IPv6AddressStatus : uint8_t
{
    Active = 0,
    Disabled = 1,
};

namespace IPv6RouterControlFlag
{
constexpr uint8_t Static = 0;
constexpr uint8_t Dynamic = 1;
}; // namespace IPv6RouterControlFlag

// LAN Handler specific response codes
constexpr Cc ccParamNotSupported = 0x80;
constexpr Cc ccParamSetLocked = 0x81;
constexpr Cc ccParamReadOnly = 0x82;

// VLANs are a 12-bit value
constexpr uint16_t VLAN_VALUE_MASK = 0x0fff;
constexpr uint16_t VLAN_ENABLE_FLAG = 0x8000;

// Arbitrary v6 Address Limits to prevent too much output in ipmitool
constexpr uint8_t MAX_IPV6_STATIC_ADDRESSES = 15;
constexpr uint8_t MAX_IPV6_DYNAMIC_ADDRESSES = 15;

// Prefix length limits of phosphor-networkd
constexpr uint8_t MIN_IPV4_PREFIX_LENGTH = 1;
constexpr uint8_t MAX_IPV4_PREFIX_LENGTH = 32;
constexpr uint8_t MIN_IPV6_PREFIX_LENGTH = 1;
constexpr uint8_t MAX_IPV6_PREFIX_LENGTH = 128;

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

/** @brief A trivial helper used to determine if two PODs are equal
 *
 *  @params[in] a - The first object to compare
 *  @params[in] b - The second object to compare
 *  @return True if the objects are the same bytewise
 */
template <typename T>
bool equal(const T& a, const T& b)
{
    static_assert(std::is_trivially_copyable_v<T>);
    return std::memcmp(&a, &b, sizeof(T)) == 0;
}

/** @brief Copies bytes from an array into a trivially copyable container
 *
 *  @params[out] t     - The container receiving the data
 *  @params[in]  bytes - The data to copy
 */
template <size_t N, typename T>
void copyInto(T& t, const std::array<uint8_t, N>& bytes)
{
    static_assert(std::is_trivially_copyable_v<T>);
    static_assert(N == sizeof(T));
    std::memcpy(&t, bytes.data(), bytes.size());
}

/** @brief Gets a generic view of the bytes in the input container
 *
 *  @params[in] t - The data to reference
 *  @return A string_view referencing the bytes in the container
 */
template <typename T>
std::string_view dataRef(const T& t)
{
    static_assert(std::is_trivially_copyable_v<T>);
    return {reinterpret_cast<const char*>(&t), sizeof(T)};
}

/** @brief Determines the ethernet interface name corresponding to a channel
 *         Tries to map a VLAN object first so that the address information
 *         is accurate. Otherwise it gets the standard ethernet interface.
 *
 *  @param[in] bus     - The bus object used for lookups
 *  @param[in] channel - The channel id corresponding to an ethernet interface
 *  @return Ethernet interface service and object path if it exists
 */
std::optional<ChannelParams> maybeGetChannelParams(sdbusplus::bus_t& bus,
                                                   uint8_t channel);

/** @brief A trivial helper around maybeGetChannelParams() that throws an
 *         exception when it is unable to acquire parameters for the channel.
 *
 *  @param[in] bus     - The bus object used for lookups
 *  @param[in] channel - The channel id corresponding to an ethernet interface
 *  @return Ethernet interface service and object path
 */
ChannelParams getChannelParams(sdbusplus::bus_t& bus, uint8_t channel);

/** @brief Trivializes using parameter getter functions by providing a bus
 *         and channel parameters automatically.
 *
 *  @param[in] channel - The channel id corresponding to an ethernet interface
 *  ...
 */
template <auto func, typename... Args>
auto channelCall(uint8_t channel, Args&&... args)
{
    sdbusplus::bus_t bus(ipmid_get_sd_bus_connection());
    auto params = getChannelParams(bus, channel);
    return std::invoke(func, bus, params, std::forward<Args>(args)...);
}

/** @brief Generic paramters for different address families */
template <int family>
struct AddrFamily
{
};

/** @brief Parameter specialization for IPv4 */
template <>
struct AddrFamily<AF_INET>
{
    using addr = in_addr;
    static constexpr auto protocol =
        sdbusplus::xyz::openbmc_project::Network::server::IP::Protocol::IPv4;
    static constexpr size_t maxStrLen = INET6_ADDRSTRLEN;
    static constexpr uint8_t defaultPrefix = 32;
    static constexpr char propertyGateway[] = "DefaultGateway";
};

/** @brief Parameter specialization for IPv6 */
template <>
struct AddrFamily<AF_INET6>
{
    using addr = in6_addr;
    static constexpr auto protocol =
        sdbusplus::xyz::openbmc_project::Network::server::IP::Protocol::IPv6;
    static constexpr size_t maxStrLen = INET6_ADDRSTRLEN;
    static constexpr uint8_t defaultPrefix = 128;
    static constexpr char propertyGateway[] = "DefaultGateway6";
};

/** @brief Interface Neighbor configuration parameters */
template <int family>
struct IfNeigh
{
    std::string path;
    typename AddrFamily<family>::addr ip;
    ether_addr mac;
};

/** @brief Interface IP Address configuration parameters */
template <int family>
struct IfAddr
{
    std::string path;
    typename AddrFamily<family>::addr address;
    sdbusplus::xyz::openbmc_project::Network::server::IP::AddressOrigin origin;
    uint8_t prefix;
};

/** @brief Valid address origins for IPv6 */
static inline const std::unordered_set<
    sdbusplus::xyz::openbmc_project::Network::server::IP::AddressOrigin>
    originsV6Static = {sdbusplus::xyz::openbmc_project::Network::server::IP::
                           AddressOrigin::Static};
static inline const std::unordered_set<
    sdbusplus::xyz::openbmc_project::Network::server::IP::AddressOrigin>
    originsV6Dynamic = {
        sdbusplus::xyz::openbmc_project::Network::server::IP::AddressOrigin::
            DHCP,
        sdbusplus::xyz::openbmc_project::Network::server::IP::AddressOrigin::
            SLAAC,
};

/** @brief A lazy lookup mechanism for iterating over object properties stored
 *         in DBus. This will only perform the object lookup when needed, and
 *         retains a cache of previous lookups to speed up future iterations.
 */
class ObjectLookupCache
{
  public:
    using PropertiesCache = std::unordered_map<std::string, PropertyMap>;

    /** @brief Creates a new ObjectLookupCache for the interface on the bus
     *         NOTE: The inputs to this object must outlive the object since
     *         they are only referenced by it.
     *
     *  @param[in] bus    - The bus object used for lookups
     *  @param[in] params - The parameters for the channel
     *  @param[in] intf   - The interface we are looking up
     */
    ObjectLookupCache(sdbusplus::bus_t& bus, const ChannelParams& params,
                      const char* intf) :
        bus(bus),
        params(params), intf(intf),
        objs(getAllDbusObjects(bus, params.logicalPath, intf, ""))
    {
    }

    class iterator : public ObjectTree::const_iterator
    {
      public:
        using value_type = PropertiesCache::value_type;

        iterator(ObjectTree::const_iterator it, ObjectLookupCache& container) :
            ObjectTree::const_iterator(it), container(container),
            ret(container.cache.end())
        {
        }
        value_type& operator*()
        {
            ret = container.get(ObjectTree::const_iterator::operator*().first);
            return *ret;
        }
        value_type* operator->()
        {
            return &operator*();
        }

      private:
        ObjectLookupCache& container;
        PropertiesCache::iterator ret;
    };

    iterator begin() noexcept
    {
        return iterator(objs.begin(), *this);
    }

    iterator end() noexcept
    {
        return iterator(objs.end(), *this);
    }

  private:
    sdbusplus::bus_t& bus;
    const ChannelParams& params;
    const char* const intf;
    const ObjectTree objs;
    PropertiesCache cache;

    /** @brief Gets a cached copy of the object properties if possible
     *         Otherwise performs a query on DBus to look them up
     *
     *  @param[in] path - The object path to lookup
     *  @return An iterator for the specified object path + properties
     */
    PropertiesCache::iterator get(const std::string& path)
    {
        auto it = cache.find(path);
        if (it != cache.end())
        {
            return it;
        }
        auto properties = getAllDbusProperties(bus, params.service, path, intf);
        return cache.insert({path, std::move(properties)}).first;
    }
};

/** @brief Turns an IP address string into the network byte order form
 *         NOTE: This version strictly validates family matches
 *
 *  @param[in] address - The string form of the address
 *  @return A network byte order address or none if conversion failed
 */
template <int family>
std::optional<typename AddrFamily<family>::addr>
    maybeStringToAddr(const char* address)
{
    typename AddrFamily<family>::addr ret;
    if (inet_pton(family, address, &ret) == 1)
    {
        return ret;
    }
    return std::nullopt;
}

/** @brief Turns an IP address string into the network byte order form
 *         NOTE: This version strictly validates family matches
 *
 *  @param[in] address - The string form of the address
 *  @return A network byte order address
 */
template <int family>
typename AddrFamily<family>::addr stringToAddr(const char* address)
{
    auto ret = maybeStringToAddr<family>(address);
    if (!ret)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to convert IP Address",
            phosphor::logging::entry("FAMILY=%d", family),
            phosphor::logging::entry("ADDRESS=%s", address));
        phosphor::logging::elog<
            sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure>();
    }
    return *ret;
}

/** @brief Turns an IP address in network byte order into a string
 *
 *  @param[in] address - The string form of the address
 *  @return A network byte order address
 */
template <int family>
std::string addrToString(const typename AddrFamily<family>::addr& address)
{
    std::string ret(AddrFamily<family>::maxStrLen, '\0');
    inet_ntop(family, &address, ret.data(), ret.size());
    ret.resize(strlen(ret.c_str()));
    return ret;
}

/** @brief Converts a human readable MAC string into MAC bytes
 *
 *  @param[in] mac - The MAC string
 *  @return MAC in bytes
 */
ether_addr stringToMAC(const char* mac);
/** @brief Searches the ip object lookup cache for an address matching
 *         the input parameters. NOTE: The index lacks stability across address
 *         changes since the network daemon has no notion of stable indicies.
 *
 *  @param[in] bus     - The bus object used for lookups
 *  @param[in] params  - The parameters for the channel
 *  @param[in] idx     - The index of the desired address on the interface
 *  @param[in] origins - The allowed origins for the address objects
 *  @param[in] ips     - The object lookup cache holding all of the address info
 *  @return The address and prefix if it was found
 */
template <int family>
std::optional<IfAddr<family>> findIfAddr(
    [[maybe_unused]] sdbusplus::bus_t& bus,
    [[maybe_unused]] const ChannelParams& params, uint8_t idx,
    const std::unordered_set<
        sdbusplus::xyz::openbmc_project::Network::server::IP::AddressOrigin>&
        origins,
    ObjectLookupCache& ips)
{
    for (const auto& [path, properties] : ips)
    {
        const auto& addrStr = std::get<std::string>(properties.at("Address"));
        auto addr = maybeStringToAddr<family>(addrStr.c_str());
        if (!addr)
        {
            continue;
        }

        sdbusplus::xyz::openbmc_project::Network::server::IP::AddressOrigin
            origin = sdbusplus::xyz::openbmc_project::Network::server::IP::
                convertAddressOriginFromString(
                    std::get<std::string>(properties.at("Origin")));
        if (origins.find(origin) == origins.end())
        {
            continue;
        }

        if (idx > 0)
        {
            idx--;
            continue;
        }

        IfAddr<family> ifaddr;
        ifaddr.path = path;
        ifaddr.address = *addr;
        ifaddr.prefix = std::get<uint8_t>(properties.at("PrefixLength"));
        ifaddr.origin = origin;
        return ifaddr;
    }

    return std::nullopt;
}
/** @brief Trivial helper around findIfAddr that simplifies calls
 *         for one off lookups. Don't use this if you intend to do multiple
 *         lookups at a time.
 *
 *  @param[in] bus     - The bus object used for lookups
 *  @param[in] params  - The parameters for the channel
 *  @param[in] idx     - The index of the desired address on the interface
 *  @param[in] origins - The allowed origins for the address objects
 *  @return The address and prefix if it was found
 */
template <int family>
auto getIfAddr(
    sdbusplus::bus_t& bus, const ChannelParams& params, uint8_t idx,
    const std::unordered_set<
        sdbusplus::xyz::openbmc_project::Network::server::IP::AddressOrigin>&
        origins)
{
    ObjectLookupCache ips(bus, params, INTF_IP);
    return findIfAddr<family>(bus, params, idx, origins, ips);
}

/** @brief Determines if the ethernet interface is using DHCP
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel
 *  @return DHCPConf enumeration
 */
sdbusplus::xyz::openbmc_project::Network::server::EthernetInterface::DHCPConf
    getDHCPProperty(sdbusplus::bus_t& bus, const ChannelParams& params);

/** @brief Sets the DHCP v6 state on the given interface
 *
 *  @param[in] bus           - The bus object used for lookups
 *  @param[in] params        - The parameters for the channel
 *  @param[in] requestedDhcp - DHCP state to assign (none, v6, both)
 *  @param[in] defaultMode   - True: Use algorithmic assignment
 *                             False: requestedDhcp assigned unconditionally
 */
void setDHCPv6Property(sdbusplus::bus_t& bus, const ChannelParams& params,
                       const sdbusplus::xyz::openbmc_project::Network::server::
                           EthernetInterface::DHCPConf requestedDhcp,
                       const bool defaultMode);

/** @brief Reconfigures the IPv6 address info configured for the interface
 *
 *  @param[in] bus     - The bus object used for lookups
 *  @param[in] params  - The parameters for the channel
 *  @param[in] idx     - The address index to operate on
 *  @param[in] address - The new address
 *  @param[in] prefix  - The new address prefix
 */
void reconfigureIfAddr6(sdbusplus::bus_t& bus, const ChannelParams& params,
                        uint8_t idx, const in6_addr& address, uint8_t prefix);

/** @brief Retrieves the current gateway for the address family on the system
 *         NOTE: The gateway is per channel instead of the system wide one.
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel
 *  @return An address representing the gateway address if it exists
 */
template <int family>
std::optional<typename AddrFamily<family>::addr>
    getGatewayProperty(sdbusplus::bus_t& bus, const ChannelParams& params)
{
    auto objPath = "/xyz/openbmc_project/network/" + params.ifname;
    auto gatewayStr = std::get<std::string>(
        getDbusProperty(bus, params.service, objPath, INTF_ETHERNET,
                        AddrFamily<family>::propertyGateway));
    if (gatewayStr.empty())
    {
        return std::nullopt;
    }
    return stringToAddr<family>(gatewayStr.c_str());
}

template <int family>
std::optional<IfNeigh<family>>
    findStaticNeighbor(sdbusplus::bus_t&, const ChannelParams&,
                       const typename AddrFamily<family>::addr& ip,
                       ObjectLookupCache& neighbors)
{
    using sdbusplus::xyz::openbmc_project::Network::server::Neighbor;
    const auto state =
        sdbusplus::xyz::openbmc_project::Network::server::convertForMessage(
            Neighbor::State::Permanent);
    for (const auto& [path, neighbor] : neighbors)
    {
        const auto& ipStr = std::get<std::string>(neighbor.at("IPAddress"));
        auto neighIP = maybeStringToAddr<family>(ipStr.c_str());
        if (!neighIP)
        {
            continue;
        }
        if (!equal(*neighIP, ip))
        {
            continue;
        }
        if (state != std::get<std::string>(neighbor.at("State")))
        {
            continue;
        }

        IfNeigh<family> ret;
        ret.path = path;
        ret.ip = ip;
        const auto& macStr = std::get<std::string>(neighbor.at("MACAddress"));
        ret.mac = stringToMAC(macStr.c_str());
        return ret;
    }

    return std::nullopt;
}

template <int family>
void createNeighbor(sdbusplus::bus_t& bus, const ChannelParams& params,
                    const typename AddrFamily<family>::addr& address,
                    const ether_addr& mac)
{
    auto newreq =
        bus.new_method_call(params.service.c_str(), params.logicalPath.c_str(),
                            INTF_NEIGHBOR_CREATE_STATIC, "Neighbor");
    std::string macStr = ether_ntoa(&mac);
    newreq.append(addrToString<family>(address), macStr);
    bus.call_noreply(newreq);
}

/** @brief Deletes the dbus object. Ignores empty objects or objects that are
 *         missing from the bus.
 *
 *  @param[in] bus     - The bus object used for lookups
 *  @param[in] service - The name of the service
 *  @param[in] path    - The path of the object to delete
 */
void deleteObjectIfExists(sdbusplus::bus_t& bus, const std::string& service,
                          const std::string& path);

/** @brief Sets the value for the default gateway of the channel
 *
 *  @param[in] bus     - The bus object used for lookups
 *  @param[in] params  - The parameters for the channel
 *  @param[in] gateway - Gateway address to apply
 */
template <int family>
void setGatewayProperty(sdbusplus::bus_t& bus, const ChannelParams& params,
                        const typename AddrFamily<family>::addr& address)
{
    // Save the old gateway MAC address if it exists so we can recreate it
    auto gateway = getGatewayProperty<family>(bus, params);
    std::optional<IfNeigh<family>> neighbor;
    if (gateway)
    {
        ObjectLookupCache neighbors(bus, params, INTF_NEIGHBOR);
        neighbor = findStaticNeighbor<family>(bus, params, *gateway, neighbors);
    }

    auto objPath = "/xyz/openbmc_project/network/" + params.ifname;
    setDbusProperty(bus, params.service, objPath, INTF_ETHERNET,
                    AddrFamily<family>::propertyGateway,
                    addrToString<family>(address));

    // Restore the gateway MAC if we had one
    if (neighbor)
    {
        deleteObjectIfExists(bus, params.service, neighbor->path);
        createNeighbor<family>(bus, params, address, neighbor->mac);
    }
}

/** @enum SolConfParam
 *
 *  using for Set/Get SOL configuration parameters command.
 */
enum class SolConfParam : uint8_t
{
    Progress,       //!< Set In Progress.
    Enable,         //!< SOL Enable.
    Authentication, //!< SOL Authentication.
    Accumulate,     //!< Character Accumulate Interval & Send Threshold.
    Retry,          //!< SOL Retry.
    NonVbitrate,    //!< SOL non-volatile bit rate.
    Vbitrate,       //!< SOL volatile bit rate.
    Channel,        //!< SOL payload channel.
    Port,           //!< SOL payload port.
};

constexpr uint8_t ipmiCCParamNotSupported = 0x80;
constexpr uint8_t ipmiCCWriteReadParameter = 0x82;

} // namespace transport
} // namespace ipmi
