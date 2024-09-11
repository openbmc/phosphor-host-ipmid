#pragma once

#include "app/channel.hpp"
#include "transportconstants.hpp"
#include "user_channel/cipher_mgmt.hpp"

#include <ipmid/api-types.hpp>
#include <ipmid/api.hpp>
#include <ipmid/message.hpp>
#include <ipmid/message/types.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/exception.hpp>
#include <stdplus/net/addr/ether.hpp>
#include <stdplus/net/addr/ip.hpp>
#include <stdplus/str/conv.hpp>
#include <stdplus/zstring_view.hpp>
#include <user_channel/channel_layer.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/Network/EthernetInterface/server.hpp>
#include <xyz/openbmc_project/Network/IP/server.hpp>
#include <xyz/openbmc_project/Network/Neighbor/server.hpp>

#include <cinttypes>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace ipmi
{
namespace transport
{

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
std::optional<ChannelParams>
    maybeGetChannelParams(sdbusplus::bus_t& bus, uint8_t channel);

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
{};

/** @brief Parameter specialization for IPv4 */
template <>
struct AddrFamily<AF_INET>
{
    using addr = stdplus::In4Addr;
    static constexpr auto protocol =
        sdbusplus::server::xyz::openbmc_project::network::IP::Protocol::IPv4;
    static constexpr size_t maxStrLen = INET6_ADDRSTRLEN;
    static constexpr uint8_t defaultPrefix = 32;
    static constexpr char propertyGateway[] = "DefaultGateway";
};

/** @brief Parameter specialization for IPv6 */
template <>
struct AddrFamily<AF_INET6>
{
    using addr = stdplus::In6Addr;
    static constexpr auto protocol =
        sdbusplus::server::xyz::openbmc_project::network::IP::Protocol::IPv6;
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
    stdplus::EtherAddr mac;
};

/** @brief Interface IP Address configuration parameters */
template <int family>
struct IfAddr
{
    std::string path;
    typename AddrFamily<family>::addr address;
    sdbusplus::server::xyz::openbmc_project::network::IP::AddressOrigin origin;
    uint8_t prefix;
};

/** @brief Valid address origins for IPv6 */
static inline const std::unordered_set<
    sdbusplus::server::xyz::openbmc_project::network::IP::AddressOrigin>
    originsV6Static = {sdbusplus::server::xyz::openbmc_project::network::IP::
                           AddressOrigin::Static};
static inline const std::unordered_set<
    sdbusplus::server::xyz::openbmc_project::network::IP::AddressOrigin>
    originsV6Dynamic = {
        sdbusplus::server::xyz::openbmc_project::network::IP::AddressOrigin::
            DHCP,
        sdbusplus::server::xyz::openbmc_project::network::IP::AddressOrigin::
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
        bus(bus), params(params), intf(intf),
        objs(getAllDbusObjects(bus, params.logicalPath, intf, ""))
    {}

    class iterator : public ObjectTree::const_iterator
    {
      public:
        using value_type = PropertiesCache::value_type;

        iterator(ObjectTree::const_iterator it, ObjectLookupCache& container) :
            ObjectTree::const_iterator(it), container(container),
            ret(container.cache.end())
        {}
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
        sdbusplus::server::xyz::openbmc_project::network::IP::AddressOrigin>&
        origins,
    ObjectLookupCache& ips)
{
    for (const auto& [path, properties] : ips)
    {
        try
        {
            typename AddrFamily<family>::addr addr;
            addr = stdplus::fromStr<typename AddrFamily<family>::addr>(
                std::get<std::string>(properties.at("Address")));

            sdbusplus::server::xyz::openbmc_project::network::IP::AddressOrigin
                origin = sdbusplus::server::xyz::openbmc_project::network::IP::
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
            ifaddr.address = addr;
            ifaddr.prefix = std::get<uint8_t>(properties.at("PrefixLength"));
            ifaddr.origin = origin;

            return ifaddr;
        }
        catch (...)
        {
            continue;
        }
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
        sdbusplus::server::xyz::openbmc_project::network::IP::AddressOrigin>&
        origins)
{
    ObjectLookupCache ips(bus, params, INTF_IP);
    return findIfAddr<family>(bus, params, idx, origins, ips);
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
                        uint8_t idx, stdplus::In6Addr address, uint8_t prefix);

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
    return stdplus::fromStr<typename AddrFamily<family>::addr>(gatewayStr);
}

template <int family>
std::optional<IfNeigh<family>> findStaticNeighbor(
    sdbusplus::bus_t&, const ChannelParams&,
    typename AddrFamily<family>::addr ip, ObjectLookupCache& neighbors)
{
    using sdbusplus::server::xyz::openbmc_project::network::Neighbor;
    const auto state =
        sdbusplus::common::xyz::openbmc_project::network::convertForMessage(
            Neighbor::State::Permanent);
    for (const auto& [path, neighbor] : neighbors)
    {
        try
        {
            typename AddrFamily<family>::addr neighIP;
            neighIP = stdplus::fromStr<typename AddrFamily<family>::addr>(
                std::get<std::string>(neighbor.at("IPAddress")));

            if (neighIP != ip)
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
            ret.mac = stdplus::fromStr<stdplus::EtherAddr>(
                std::get<std::string>(neighbor.at("MACAddress")));

            return ret;
        }
        catch (...)
        {
            continue;
        }
    }

    return std::nullopt;
}

template <int family>
void createNeighbor(sdbusplus::bus_t& bus, const ChannelParams& params,
                    typename AddrFamily<family>::addr address,
                    stdplus::EtherAddr mac)
{
    auto newreq =
        bus.new_method_call(params.service.c_str(), params.logicalPath.c_str(),
                            INTF_NEIGHBOR_CREATE_STATIC, "Neighbor");
    stdplus::ToStrHandle<stdplus::ToStr<stdplus::EtherAddr>> macToStr;
    stdplus::ToStrHandle<stdplus::ToStr<typename AddrFamily<family>::addr>>
        addrToStr;
    newreq.append(addrToStr(address), macToStr(mac));
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
                        typename AddrFamily<family>::addr address)
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
                    stdplus::toStr(address));

    // Restore the gateway MAC if we had one
    if (neighbor)
    {
        deleteObjectIfExists(bus, params.service, neighbor->path);
        createNeighbor<family>(bus, params, address, neighbor->mac);
    }
}

} // namespace transport
} // namespace ipmi
