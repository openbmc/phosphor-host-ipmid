#include "app/channel.hpp"

#include <arpa/inet.h>
#include <netinet/ether.h>

#include <array>
#include <bitset>
#include <cinttypes>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <functional>
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
#include <xyz/openbmc_project/Network/IP/server.hpp>

using phosphor::logging::commit;
using phosphor::logging::elog;
using phosphor::logging::entry;
using phosphor::logging::level;
using phosphor::logging::log;
using sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
using sdbusplus::xyz::openbmc_project::Network::server::IP;

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

// LAN Handler specific response codes
constexpr Cc ccParamNotSupported = 0x80;
constexpr Cc ccParamSetLocked = 0x81;
constexpr Cc ccParamReadOnly = 0x82;

// VLANs are a 12-bit value
constexpr uint16_t VLAN_VALUE_MASK = 0x0fff;
constexpr uint16_t VLAN_ENABLE_FLAG = 0x8000;

// D-Bus Network Daemon definitions
constexpr auto PATH_ROOT = "/xyz/openbmc_project/network";
constexpr auto PATH_SYSTEMCONFIG = "/xyz/openbmc_project/network/config";

constexpr auto INTF_SYSTEMCONFIG =
    "xyz.openbmc_project.Network.SystemConfiguration";
constexpr auto INTF_ETHERNET = "xyz.openbmc_project.Network.EthernetInterface";
constexpr auto INTF_IP = "xyz.openbmc_project.Network.IP";
constexpr auto INTF_IP_CREATE = "xyz.openbmc_project.Network.IP.Create";
constexpr auto INTF_MAC = "xyz.openbmc_project.Network.MACAddress";
constexpr auto INTF_VLAN = "xyz.openbmc_project.Network.VLAN";
constexpr auto INTF_VLAN_CREATE = "xyz.openbmc_project.Network.VLAN.Create";

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
    static constexpr auto protocol = IP::Protocol::IPv4;
    static constexpr size_t maxStrLen = INET6_ADDRSTRLEN;
    static constexpr uint8_t defaultPrefix = 32;
    static constexpr char propertyGateway[] = "DefaultGateway";
};

/** @brief Valid address origins for IPv4 */
const std::unordered_set<IP::AddressOrigin> originsV4 = {
    IP::AddressOrigin::Static,
    IP::AddressOrigin::DHCP,
};

/** @brief Interface IP Address configuration parameters */
template <int family>
struct IfAddr
{
    std::string path;
    typename AddrFamily<family>::addr address;
    IP::AddressOrigin origin;
    uint8_t prefix;
};

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
    VLANId = 20,
    CiphersuiteSupport = 22,
    CiphersuiteEntries = 23,
    oemCmdStart = 192,
    oemCmdEnd = 255,
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
std::optional<ChannelParams> maybeGetChannelParams(sdbusplus::bus::bus& bus,
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
    return std::move(params);
}

/** @brief A trivial helper around maybeGetChannelParams() that throws an
 *         exception when it is unable to acquire parameters for the channel.
 *
 *  @param[in] bus     - The bus object used for lookups
 *  @param[in] channel - The channel id corresponding to an ethernet interface
 *  @return Ethernet interface service and object path
 */
ChannelParams getChannelParams(sdbusplus::bus::bus& bus, uint8_t channel)
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

/** @brief Trivializes using parameter getter functions by providing a bus
 *         and channel parameters automatically.
 *
 *  @param[in] channel - The channel id corresponding to an ethernet interface
 *  ...
 */
template <auto func, typename... Args>
auto channelCall(uint8_t channel, Args&&... args)
{
    sdbusplus::bus::bus bus(ipmid_get_sd_bus_connection());
    auto params = getChannelParams(bus, channel);
    return std::invoke(func, bus, params, std::forward<Args>(args)...);
}

/** @brief Determines if the ethernet interface is using DHCP
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel
 *  @return True if DHCP is enabled, false otherwise
 */
bool getDHCPProperty(sdbusplus::bus::bus& bus, const ChannelParams& params)
{
    return std::get<bool>(getDbusProperty(
        bus, params.service, params.logicalPath, INTF_ETHERNET, "DHCPEnabled"));
}

/** @brief Sets the system value for DHCP on the given interface
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel
 *  @param[in] on     - Whether or not to enable DHCP
 */
void setDHCPProperty(sdbusplus::bus::bus& bus, const ChannelParams& params,
                     bool on)
{
    setDbusProperty(bus, params.service, params.logicalPath, INTF_ETHERNET,
                    "DHCPEnabled", on);
}

/** @brief Converts a human readable MAC string into MAC bytes
 *
 *  @param[in] mac - The MAC string
 *  @return MAC in bytes
 */
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
ether_addr getMACProperty(sdbusplus::bus::bus& bus, const ChannelParams& params)
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
void setMACProperty(sdbusplus::bus::bus& bus, const ChannelParams& params,
                    const ether_addr& mac)
{
    std::string macStr = ether_ntoa(&mac);
    setDbusProperty(bus, params.service, params.ifPath, INTF_MAC, "MACAddress",
                    macStr);
}

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
        log<level::ERR>("Failed to convert IP Address",
                        entry("FAMILY=%d", family),
                        entry("ADDRESS=%s", address));
        elog<InternalFailure>();
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

/** @brief Retrieves the current gateway for the address family on the system
 *         NOTE: The gateway is currently system wide and not per channel
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel
 *  @return An address representing the gateway address if it exists
 */
template <int family>
std::optional<typename AddrFamily<family>::addr>
    getGatewayProperty(sdbusplus::bus::bus& bus, const ChannelParams& params)
{
    auto gatewayStr = std::get<std::string>(getDbusProperty(
        bus, params.service, PATH_SYSTEMCONFIG, INTF_SYSTEMCONFIG,
        AddrFamily<family>::propertyGateway));
    if (gatewayStr.empty())
    {
        return std::nullopt;
    }
    return stringToAddr<family>(gatewayStr.c_str());
}

/** @brief Sets the system wide value for the default gateway
 *
 *  @param[in] bus     - The bus object used for lookups
 *  @param[in] params  - The parameters for the channel
 *  @param[in] gateway - Gateway address to apply
 */
template <int family>
void setGatewayProperty(sdbusplus::bus::bus& bus, const ChannelParams& params,
                        const typename AddrFamily<family>::addr& address)
{
    setDbusProperty(bus, params.service, PATH_SYSTEMCONFIG, INTF_SYSTEMCONFIG,
                    AddrFamily<family>::propertyGateway,
                    addrToString<family>(address));
}

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
    ObjectLookupCache(sdbusplus::bus::bus& bus, const ChannelParams& params,
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
    sdbusplus::bus::bus& bus;
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
std::optional<IfAddr<family>>
    findIfAddr(sdbusplus::bus::bus& bus, const ChannelParams& params,
               uint8_t idx,
               const std::unordered_set<IP::AddressOrigin>& origins,
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

        IP::AddressOrigin origin = IP::convertAddressOriginFromString(
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
        return std::move(ifaddr);
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
auto getIfAddr(sdbusplus::bus::bus& bus, const ChannelParams& params,
               uint8_t idx,
               const std::unordered_set<IP::AddressOrigin>& origins)
{
    ObjectLookupCache ips(bus, params, INTF_IP);
    return findIfAddr<family>(bus, params, idx, origins, ips);
}

/** @brief Deletes the dbus object. Ignores empty objects or objects that are
 *         missing from the bus.
 *
 *  @param[in] bus     - The bus object used for lookups
 *  @param[in] service - The name of the service
 *  @param[in] path    - The path of the object to delete
 */
void deleteObjectIfExists(sdbusplus::bus::bus& bus, const std::string& service,
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
    catch (const sdbusplus::exception::SdBusError& e)
    {
        if (strcmp(e.name(), "org.freedesktop.DBus.Error.UnknownObject") != 0)
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
void createIfAddr(sdbusplus::bus::bus& bus, const ChannelParams& params,
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
auto getIfAddr4(sdbusplus::bus::bus& bus, const ChannelParams& params)
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
void reconfigureIfAddr4(sdbusplus::bus::bus& bus, const ChannelParams& params,
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

/** @brief Gets the vlan ID configured on the interface
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel
 *  @return VLAN id or the standard 0 for no VLAN
 */
uint16_t getVLANProperty(sdbusplus::bus::bus& bus, const ChannelParams& params)
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
void deconfigureChannel(sdbusplus::bus::bus& bus, ChannelParams& params)
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
    setDHCPProperty(bus, params, false);
}

/** @brief Creates a new VLAN on the specified interface
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel
 *  @param[in] vlan   - The id of the new vlan
 */
void createVLAN(sdbusplus::bus::bus& bus, ChannelParams& params, uint16_t vlan)
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
void reconfigureVLAN(sdbusplus::bus::bus& bus, ChannelParams& params,
                     uint16_t vlan)
{
    // Unfortunatetly we don't have built-in functions to migrate our interface
    // customizations to new VLAN interfaces, or have some kind of decoupling.
    // We therefore must retain all of our old information, setup the new VLAN
    // configuration, then restore the old info.

    // Save info from the old logical interface
    ObjectLookupCache ips(bus, params, INTF_IP);
    auto ifaddr4 = findIfAddr<AF_INET>(bus, params, 0, originsV4, ips);
    auto dhcp = getDHCPProperty(bus, params);

    deconfigureChannel(bus, params);
    createVLAN(bus, params, vlan);

    // Re-establish the saved settings
    setDHCPProperty(bus, params, dhcp);
    if (ifaddr4)
    {
        createIfAddr<AF_INET>(bus, params, ifaddr4->address, ifaddr4->prefix);
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
    return 32 - __builtin_ctz(x);
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
 *      EXTRA_OECONF_append = " --enable-transport-oem=yes"
 *   Create a do_compile_prepend()/do_install_append method in your
 *   bbappend file to copy the file to the build directory.
 *   Add:
 *   PROJECT_SRC_DIR := "${THISDIR}/${PN}"
 *   # Copy the "strong" functions into the working directory, overriding the
 *   # placeholder functions.
 *   do_compile_prepend(){
 *      cp -f ${PROJECT_SRC_DIR}/transporthandler_oem.cpp ${S}
 *   }
 *
 *   # Clean up after complilation has completed
 *   do_install_append(){
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

RspType<> setLanOem(uint8_t channel, uint8_t parameter, message::Payload& req)
{
    req.trailingOk = true;
    return response(ccParamNotSupported);
}

RspType<message::Payload> getLanOem(uint8_t channel, uint8_t parameter,
                                    uint8_t set, uint8_t block)
{
    return response(ccParamNotSupported);
}

RspType<> setLan(uint4_t channelBits, uint4_t, uint8_t parameter,
                 message::Payload& req)
{
    auto channel = static_cast<uint8_t>(channelBits);
    if (!doesDeviceExist(channel))
    {
        req.trailingOk = true;
        return responseInvalidFieldRequest();
    }

    LanParam cmd = static_cast<LanParam>(parameter);
    switch (cmd)
    {
        case LanParam::SetStatus:
        {
            uint2_t flag;
            uint6_t rsvd;
            if (req.unpack(flag, rsvd) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
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
            return response(ccParamNotSupported);
        }
        case LanParam::IP:
        {
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
            switch (static_cast<IPSrc>(static_cast<uint8_t>(flag)))
            {
                case IPSrc::DHCP:
                {
                    channelCall<setDHCPProperty>(channel, true);
                    return responseSuccess();
                }
                case IPSrc::Unspecified:
                case IPSrc::Static:
                case IPSrc::BIOS:
                case IPSrc::BMC:
                {
                    channelCall<setDHCPProperty>(channel, false);
                    return responseSuccess();
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
            channelCall<setMACProperty>(channel, mac);
            return responseSuccess();
        }
        case LanParam::SubnetMask:
        {
            in_addr netmask;
            std::array<uint8_t, sizeof(netmask)> bytes;
            if (req.unpack(bytes) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }
            copyInto(netmask, bytes);
            channelCall<reconfigureIfAddr4>(channel, std::nullopt,
                                            netmaskToPrefix(netmask));
            return responseSuccess();
        }
        case LanParam::Gateway1:
        {
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
        case LanParam::VLANId:
        {
            uint16_t vlanData;
            if (req.unpack(vlanData) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }
            if ((vlanData & VLAN_ENABLE_FLAG) == 0)
            {
                lastDisabledVlan[channel] = vlanData & VLAN_VALUE_MASK;
                vlanData = 0;
            }
            channelCall<reconfigureVLAN>(channel, vlanData & VLAN_VALUE_MASK);
            return responseSuccess();
        }
        case LanParam::CiphersuiteSupport:
        case LanParam::CiphersuiteEntries:
        {
            req.trailingOk = true;
            return response(ccParamReadOnly);
        }
        default:
            if ((cmd >= LanParam::oemCmdStart) && (cmd <= LanParam::oemCmdEnd))
            {
                return setLanOem(channel, parameter, req);
            }
    }

    req.trailingOk = true;
    return response(ccParamNotSupported);
}

RspType<message::Payload> getLan(uint4_t channelBits, uint3_t, bool revOnly,
                                 uint8_t parameter, uint8_t set, uint8_t block)
{
    message::Payload ret;
    constexpr uint8_t current_revision = 0x11;
    ret.pack(current_revision);

    if (revOnly)
    {
        return responseSuccess(std::move(ret));
    }

    auto channel = static_cast<uint8_t>(channelBits);
    if (!doesDeviceExist(channel))
    {
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

    LanParam cmd = static_cast<LanParam>(parameter);
    switch (cmd)
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
            ret.pack(static_cast<uint2_t>(status), uint6_t{});
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
            if (channelCall<getDHCPProperty>(channel))
            {
                src = IPSrc::DHCP;
            }
            ret.pack(static_cast<uint4_t>(src), uint4_t{});
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
            if (!listInit)
            {
                return responseUnspecifiedError();
            }
            ret.pack(static_cast<uint8_t>(cipherList.size() - 1));
            return responseSuccess(std::move(ret));
        }
        case LanParam::CiphersuiteEntries:
        {
            if (!listInit)
            {
                return responseUnspecifiedError();
            }
            ret.pack(cipherList);
            return responseSuccess(std::move(ret));
        }
        default:
            if ((cmd >= LanParam::oemCmdStart) && (cmd <= LanParam::oemCmdEnd))
            {
                return getLanOem(channel, parameter, set, block);
            }
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
                          ipmi::Privilege::Admin, ipmi::transport::getLan);
}
