#include <arpa/inet.h>
#include <netinet/ether.h>

#include <array>
#include <bitset>
#include <cinttypes>
#include <cstdint>
#include <cstring>
#include <functional>
#include <ipmid/api.hpp>
#include <ipmid/message.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <optional>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <user_channel/channel_layer.hpp>
#include <utility>
#include <variant>
#include <vector>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/Network/IP/server.hpp>

namespace ipmi
{
namespace transport
{

using phosphor::logging::commit;
using phosphor::logging::elog;
using phosphor::logging::entry;
using phosphor::logging::level;
using phosphor::logging::log;
using sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
using sdbusplus::xyz::openbmc_project::Network::server::IP;

// LAN Handler specific response codes
constexpr Cc ccParamNotSupported = 0x80;
constexpr Cc ccParamSetLocked = 0x81;
constexpr Cc ccParamReadOnly = 0x82;

// VLANs are a 12-bit value
constexpr uint16_t VLAN_VALUE_MASK = 0x0fff;
constexpr uint16_t VLAN_ENABLE_FLAG = 0x8000;

// PREFIX values should be restrictive by default
constexpr uint8_t DEFAULT_V4_PREFIX = 32;

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

using AnyAddr = std::variant<in_addr, in6_addr>;

struct IfAddr
{
    std::string path;
    AnyAddr address;
    IP::AddressOrigin origin;
    uint8_t prefix;
};

struct IfAddrSelector
{
    int family;
    std::unordered_set<IP::AddressOrigin> origins;
    uint8_t idx;
};

// Parameters
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
};

enum class IPSrc : uint8_t
{
    Unspecified = 0,
    Static = 1,
    DHCP = 2,
    BIOS = 3,
    BMC = 4,
};

enum class SetStatus : uint8_t
{
    Complete = 0,
    InProgress = 1,
    Commit = 2,
};

enum class AuthFlag : uint8_t
{
    MD5 = 2,
};

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

/** @brief A trivial helper around getChannelParams() that throws an exception
 *         when it is unable to acquire parameters for the channel.
 *
 *  @param[in] bus     - The bus object used for lookups
 *  @param[in] channel - The channel id corresponding to an ethernet interface
 *  @return Ethernet interface service and object path
 */
ChannelParams getChannelParamsOrError(sdbusplus::bus::bus& bus, uint8_t channel)
{
    auto params = getChannelParams(bus, channel);
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
    return std::invoke(func, bus, getChannelParamsOrError(bus, channel),
                       std::forward<Args>(args)...);
}

/** @brief Gets the vlan ID configured on the interface
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel on the ethernet interface
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

/** @brief Determines if the ethernet interface is using DHCP
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel on the ethernet interface
 *  @return True if DHCP is enabled, false otherwise
 */
bool getDHCPProperty(sdbusplus::bus::bus& bus, const ChannelParams& params)
{
    return std::get<bool>(getDbusProperty(
        bus, params.service, params.logicalPath, INTF_ETHERNET, "DHCPEnabled"));
}

void setDHCPProperty(sdbusplus::bus::bus& bus, const ChannelParams& params,
                     bool on)
{
    setDbusProperty(bus, params.service, params.logicalPath, INTF_ETHERNET,
                    "DHCPEnabled", on);
}

/** @brief Determines the MAC of the ethernet interface
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel on the ethernet interface
 *  @return The mac address of the ethernet interface
 */
ether_addr getMACProperty(sdbusplus::bus::bus& bus, const ChannelParams& params)
{
    auto macStr = std::get<std::string>(getDbusProperty(
        bus, params.service, params.ifPath, INTF_MAC, "MACAddress"));
    const ether_addr* mac = ether_aton(macStr.c_str());
    if (mac == nullptr)
    {
        logWithChannel<level::ERR>(params, "Got bad MAC from D-Bus",
                                   entry("MAC=%s", macStr.c_str()));
        elog<InternalFailure>();
    }
    return *mac;
}

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
 *  @param[in] family - The family of the address
 *  @param[in] address - The string form of the address
 *  @return A network byte order address
 */
AnyAddr stringToAddr(int family, const char* address)
{
    switch (family)
    {
        case AF_INET:
        {
            in_addr ret;
            if (inet_pton(family, address, &ret) != 1)
            {
                log<level::ERR>("Failed to convert IPv4 Address",
                                entry("FAMILY=%d", family),
                                entry("ADDRESS=%s", address));
                elog<InternalFailure>();
            }
            return ret;
        }
        case AF_INET6:
        {
            in6_addr ret;
            if (inet_pton(family, address, &ret) != 1)
            {
                log<level::ERR>("Failed to convert IPv6 Address",
                                entry("FAMILY=%d", family),
                                entry("ADDRESS=%s", address));
                elog<InternalFailure>();
            }
            return ret;
        }
        default:
            log<level::ERR>("Bad IP Origin", entry("FAMILY=%d", family),
                            entry("ADDRESS=%s", address));
            elog<InternalFailure>();
            throw std::runtime_error("unreachable");
    }
}

std::string addrToString(const AnyAddr& address)
{
    if (std::holds_alternative<in_addr>(address))
    {
        std::string ret(INET_ADDRSTRLEN, '\0');
        inet_ntop(AF_INET, &std::get<in_addr>(address), ret.data(), ret.size());
        ret.resize(strlen(ret.c_str()));
        return ret;
    }
    else if (std::holds_alternative<in6_addr>(address))
    {
        std::string ret(INET6_ADDRSTRLEN, '\0');
        inet_ntop(AF_INET6, &std::get<in6_addr>(address), ret.data(),
                  ret.size());
        ret.resize(strlen(ret.c_str()));
        return ret;
    }

    log<level::ERR>("Bad Address");
    elog<InternalFailure>();
    throw std::runtime_error("unreachable");
}

IP::Protocol addrToProtocol(const AnyAddr& address)
{
    if (std::holds_alternative<in_addr>(address))
    {
        return IP::Protocol::IPv4;
    }
    else if (std::holds_alternative<in6_addr>(address))
    {
        return IP::Protocol::IPv6;
    }

    log<level::ERR>("Bad Address");
    elog<InternalFailure>();
    throw std::runtime_error("unreachable");
}

int addrToFamily(const AnyAddr& address)
{
    if (std::holds_alternative<in_addr>(address))
    {
        return AF_INET;
    }
    else if (std::holds_alternative<in6_addr>(address))
    {
        return AF_INET6;
    }

    log<level::ERR>("Bad Address");
    elog<InternalFailure>();
    throw std::runtime_error("unreachable");
}

const char* gatewayProperty(int family)
{
    switch (family)
    {
        case AF_INET:
            return "DefaultGateway";
        case AF_INET6:
            return "DefaultGateway6";
        default:
            log<level::ERR>("Bad Gateway Family", entry("FAMILY=%d", family));
            elog<InternalFailure>();
            throw std::runtime_error("unreachable");
    }
}

/** @brief Retrieves the current gateway for the address family on the system
 *         NOTE: The gateway is currently system wide and not per channel
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel on the ethernet interface
 *  @param[in] family - The address family of the gateway
 *  @return An address representing the gateway address if it exists
 */
std::optional<AnyAddr> getGatewayProperty(sdbusplus::bus::bus& bus,
                                          const ChannelParams& params,
                                          int family)
{
    auto gatewayStr = std::get<std::string>(
        getDbusProperty(bus, params.service, PATH_SYSTEMCONFIG,
                        INTF_SYSTEMCONFIG, gatewayProperty(family)));
    if (gatewayStr.empty())
    {
        return std::nullopt;
    }
    return stringToAddr(family, gatewayStr.c_str());
}

void setGatewayProperty(sdbusplus::bus::bus& bus, const ChannelParams& params,
                        AnyAddr address)
{
    auto property = gatewayProperty(addrToFamily(address));
    setDbusProperty(bus, params.service, PATH_SYSTEMCONFIG, INTF_SYSTEMCONFIG,
                    property, addrToString(address));
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

    ObjectTree objs =
        getAllDbusObjects(bus, params.logicalPath, INTF_IP, filter);
    uint8_t idx = 0;
    for (const auto& obj : objs)
    {
        PropertyMap properties = getAllDbusProperties(
            bus, obj.second.begin()->first, obj.first, INTF_IP);

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
        ifaddr.path = obj.first;
        auto addrStr = std::get<std::string>(properties.at("Address"));
        ifaddr.address = stringToAddr(selector.family, addrStr.c_str());
        ifaddr.prefix = std::get<uint8_t>(properties.at("PrefixLength"));
        ifaddr.origin = origin;
        return std::move(ifaddr);
    }

    return std::nullopt;
}

void setIfAddr(sdbusplus::bus::bus& bus, const ChannelParams& params,
               const IfAddr& ifaddr)
{
    // Delete the old address entry if it exists
    if (!ifaddr.path.empty())
    {
        auto delreq =
            bus.new_method_call(params.service.c_str(), ifaddr.path.c_str(),
                                ipmi::DELETE_INTERFACE, "Delete");
        bus.call_noreply(delreq);
    }

    // Create the new address
    auto newreq =
        bus.new_method_call(params.service.c_str(), params.logicalPath.c_str(),
                            INTF_IP_CREATE, "IP");
    std::string protocol =
        sdbusplus::xyz::openbmc_project::Network::server::convertForMessage(
            addrToProtocol(ifaddr.address));
    newreq.append(protocol, addrToString(ifaddr.address), ifaddr.prefix, "");
    bus.call_noreply(newreq);
}

/** @brief Trivial helper for getting the IPv4 address from getIfAddrs()
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel on the ethernet interface
 *  @return The address and prefix if found
 */
std::optional<IfAddr> getIfAddr4(sdbusplus::bus::bus& bus,
                                 const ChannelParams& params)
{
    IfAddrSelector selector;
    selector.family = AF_INET;
    selector.origins = {IP::AddressOrigin::Static, IP::AddressOrigin::DHCP};
    selector.idx = 0;
    return getIfAddr(bus, params, selector);
}

void setIfAddr4(sdbusplus::bus::bus& bus, const ChannelParams& params,
                std::optional<in_addr> address, std::optional<uint8_t> prefix)
{
    auto ifaddr = getIfAddr4(bus, params);
    if (!ifaddr)
    {
        if (!address)
        {
            log<level::ERR>("Missing address for IPv4 assignment");
            elog<InternalFailure>();
        }
        ifaddr.emplace();
        ifaddr->prefix = DEFAULT_V4_PREFIX;
    }
    if (address)
    {
        ifaddr->address = *address;
    }
    if (prefix)
    {
        ifaddr->prefix = *prefix;
    }
    setIfAddr(bus, params, *ifaddr);
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

RspType<> SetLan(std::bitset<4> channelBits, std::bitset<4>, uint8_t parameter,
                 message::Payload& req)
{
    uint8_t channel = channelBits.to_ulong();
    if (!doesDeviceExist(channel))
    {
        return responseInvalidFieldRequest();
    }

    switch (static_cast<LanParam>(parameter))
    {
        case LanParam::SetStatus:
        {
            std::bitset<2> flag;
            std::bitset<6> rsvd;
            if (req.unpack(flag, rsvd) != 0)
            {
                return responseReqDataLenInvalid();
            }
            auto status = static_cast<SetStatus>(flag.to_ulong());
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
                default:
                    return responseInvalidFieldRequest();
            }
        }
        case LanParam::AuthSupport:
        {
            req.reset();
            return response(ccParamReadOnly);
        }
        case LanParam::AuthEnables:
        {
            req.reset();
            return response(ccParamNotSupported);
        }
        case LanParam::IP:
        {
            in_addr ip;
            std::array<uint8_t, sizeof(ip)> bytes;
            if (req.unpack(bytes) != 0)
            {
                return responseReqDataLenInvalid();
            }
            std::memcpy(&ip, bytes.data(), sizeof(ip));
            channelCall<setIfAddr4>(channel, ip, std::nullopt);
            return responseSuccess();
        }
        case LanParam::IPSrc:
        {
            std::bitset<4> flag;
            std::bitset<4> rsvd;
            if (req.unpack(flag, rsvd) != 0)
            {
                return responseReqDataLenInvalid();
            }
            auto src = static_cast<IPSrc>(flag.to_ulong());
            switch (src)
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
            return responseInvalidFieldRequest();
        }
        case LanParam::MAC:
        {
            ether_addr mac;
            std::array<uint8_t, sizeof(mac)> bytes;
            if (req.unpack(bytes) != 0)
            {
                return responseReqDataLenInvalid();
            }
            std::memcpy(&mac, bytes.data(), sizeof(mac));
            channelCall<setMACProperty>(channel, mac);
            return responseSuccess();
        }
        case LanParam::SubnetMask:
        {
            in_addr netmask;
            std::array<uint8_t, sizeof(netmask)> bytes;
            if (req.unpack(bytes) != 0)
            {
                return responseReqDataLenInvalid();
            }
            std::memcpy(&netmask, bytes.data(), sizeof(netmask));
            channelCall<setIfAddr4>(channel, std::nullopt,
                                    netmaskToPrefix(netmask));
            return responseSuccess();
        }
        case LanParam::Gateway1:
        {
            in_addr gateway;
            std::array<uint8_t, sizeof(gateway)> bytes;
            if (req.unpack(bytes) != 0)
            {
                return responseReqDataLenInvalid();
            }
            std::memcpy(&gateway, bytes.data(), sizeof(gateway));
            channelCall<setGatewayProperty>(channel, gateway);
            return responseSuccess();
        }
        case LanParam::VLANId:
        {
            req.reset();
            return response(ccParamNotSupported);
        }
        case LanParam::CiphersuiteSupport:
        case LanParam::CiphersuiteEntries:
        {
            req.reset();
            return response(ccParamReadOnly);
        }
    }

    req.reset();
    return response(ccParamNotSupported);
}

RspType<message::Payload> GetLan(std::bitset<4> channelBits, std::bitset<3>,
                                 bool revOnly, uint8_t parameter, uint8_t set,
                                 uint8_t block)
{
    message::Payload ret;
    constexpr uint8_t current_revision = 0x11;
    ret.pack(current_revision);

    if (revOnly)
    {
        return responseSuccess(std::move(ret));
    }

    uint8_t channel = channelBits.to_ulong();
    if (!doesDeviceExist(channel))
    {
        return responseInvalidFieldRequest();
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
            ret.pack(std::bitset<2>(static_cast<uint8_t>(status)));
            ret.pack(std::bitset<6>());
            return responseSuccess(std::move(ret));
        }
        case LanParam::AuthSupport:
        {
            std::bitset<6> support;
            support[static_cast<uint8_t>(AuthFlag::MD5)] = 1;
            ret.pack(support, std::bitset<2>());
            ret.pack(std::bitset<2>());
            return responseSuccess(std::move(ret));
        }
        case LanParam::AuthEnables:
        {
            std::bitset<6> enables;
            enables[static_cast<uint8_t>(AuthFlag::MD5)] = 1;
            ret.pack(enables, std::bitset<2>()); // Callback
            ret.pack(enables, std::bitset<2>()); // User
            ret.pack(enables, std::bitset<2>()); // Operator
            ret.pack(enables, std::bitset<2>()); // Admin
            ret.pack(enables, std::bitset<2>()); // OEM
            return responseSuccess(std::move(ret));
        }
        case LanParam::IP:
        {
            auto ifaddr = channelCall<getIfAddr4>(channel);
            in_addr addr{};
            if (ifaddr)
            {
                addr = std::get<in_addr>(ifaddr->address);
            }
            ret.pack(
                std::string_view(reinterpret_cast<char*>(&addr), sizeof(addr)));
            return responseSuccess(std::move(ret));
        }
        case LanParam::IPSrc:
        {
            IPSrc src = IPSrc::Static;
            if (channelCall<getDHCPProperty>(channel))
            {
                src = IPSrc::DHCP;
            }
            ret.pack(std::bitset<4>(static_cast<uint8_t>(src)));
            ret.pack(std::bitset<4>());
            return responseSuccess(std::move(ret));
        }
        case LanParam::MAC:
        {
            ether_addr mac = channelCall<getMACProperty>(channel);
            ret.pack(
                std::string_view(reinterpret_cast<char*>(&mac), sizeof(mac)));
            return responseSuccess(std::move(ret));
        }
        case LanParam::SubnetMask:
        {
            auto ifaddr = channelCall<getIfAddr4>(channel);
            in_addr netmask = prefixToNetmask(DEFAULT_V4_PREFIX);
            if (ifaddr)
            {
                netmask = prefixToNetmask(ifaddr->prefix);
            }
            ret.pack(std::string_view(reinterpret_cast<char*>(&netmask),
                                      sizeof(netmask)));
            return responseSuccess(std::move(ret));
        }
        case LanParam::Gateway1:
        {
            auto gateway = channelCall<getGatewayProperty>(channel, AF_INET)
                               .value_or(in_addr{});
            ret.pack(std::string_view(reinterpret_cast<char*>(&gateway),
                                      sizeof(gateway)));
            return responseSuccess(std::move(ret));
        }
        case LanParam::VLANId:
        {
            uint16_t vlan = channelCall<getVLANProperty>(channel);
            if (vlan != 0)
            {
                vlan |= VLAN_ENABLE_FLAG;
            }
            ret.pack(vlan);
            return responseSuccess(std::move(ret));
        }
        case LanParam::CiphersuiteSupport:
        case LanParam::CiphersuiteEntries:
            return response(ccParamNotSupported);
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
                          ipmi::Privilege::Admin, ipmi::transport::SetLan);
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnTransport,
                          ipmi::transport::cmdGetLanConfigParameters,
                          ipmi::Privilege::Admin, ipmi::transport::GetLan);
}
