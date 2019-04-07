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

// timer for network changes
std::unique_ptr<phosphor::Timer> networkTimer = nullptr;

constexpr auto ipv4Protocol = "xyz.openbmc_project.Network.IP.Protocol.IPv4";

std::map<int, std::unique_ptr<struct ChannelConfig_t>> channelConfig;

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

/** @brief Determines the ethernet interface name corresponding to a channel
 *
 *  @param[in] channel - The channel id corresponding to an ethernet interface
 *  @return Ethernet interface name
 */
std::string getIntf(int channel)
{
    auto intf = ipmi::getChannelName(channel);
    if (intf.empty())
    {
        log<level::ERR>("Missing ethernet interface for channel",
                        entry("CHANNEL=%d", channel));
        elog<InternalFailure>();
    }
    return intf;
}

/** @brief Determines if the ethernet interface is using DHCP
 *
 *  @param[in] bus     - The bus object used for lookups
 *  @param[in] channel - The channel id corresponding to an ethernet interface
 *  @return True if DHCP is enabled, false otherwise
 */
bool getDHCPProperty(sdbusplus::bus::bus& bus, int channel)
{
    auto intf = getIntf(channel);
    auto ethObj = ipmi::getDbusObject(bus, ipmi::network::ETHERNET_INTERFACE,
                                      ipmi::network::ROOT, intf);
    return std::get<bool>(ipmi::getDbusProperty(
        bus, ethObj.second, ethObj.first, ipmi::network::ETHERNET_INTERFACE,
        "DHCPEnabled"));
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
    sdbusplus::bus::bus bus(ipmid_get_sd_bus_connection());

    auto ethdevice = ipmi::getChannelName(channel);
    // if ethdevice is an empty string they weren't expecting this channel.
    if (ethdevice.empty())
    {
        // TODO: return error from getNetworkData()
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    auto ethIP = ethdevice + "/" + ipmi::network::IP_TYPE;
    auto channelConf = getChannelConfig(channel);

    try
    {
        switch (static_cast<LanParam>(lan_param))
        {
            case LanParam::IP:
            {
                std::string ipaddress;
                if (channelConf->ipaddr.empty())
                {
                    try
                    {
                        auto ipObjectInfo =
                            ipmi::getIPObject(bus, ipmi::network::IP_INTERFACE,
                                              ipmi::network::ROOT, ethIP);

                        auto properties = ipmi::getAllDbusProperties(
                            bus, ipObjectInfo.second, ipObjectInfo.first,
                            ipmi::network::IP_INTERFACE);

                        ipaddress =
                            variant_ns::get<std::string>(properties["Address"]);
                    }
                    // ignore the exception, as it is a valid condition that
                    // the system is not configured with any IP.
                    catch (InternalFailure& e)
                    {
                        // nothing to do.
                    }
                }
                else
                {
                    ipaddress = channelConf->ipaddr;
                }

                inet_pton(AF_INET, ipaddress.c_str(),
                          reinterpret_cast<void*>(data));
            }
            break;

            case LanParam::IPSRC:
            {
                bool dhcpEnabled;
                if (!channelConf->dhcpEnabled)
                {
                    dhcpEnabled = getDHCPProperty(bus, channel);
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
                if (!channelConf->prefix)
                {
                    try
                    {
                        auto ipObjectInfo =
                            ipmi::getIPObject(bus, ipmi::network::IP_INTERFACE,
                                              ipmi::network::ROOT, ethIP);

                        auto properties = ipmi::getAllDbusProperties(
                            bus, ipObjectInfo.second, ipObjectInfo.first,
                            ipmi::network::IP_INTERFACE);

                        prefix = std::get<uint8_t>(properties["PrefixLength"]);
                    }
                    // ignore the exception, as it is a valid condition that
                    // the system is not configured with any IP.
                    catch (InternalFailure& e)
                    {
                        // nothing to do
                    }
                }
                else
                {
                    prefix = *channelConf->prefix;
                }

                in_addr netmask = prefixToNetmask(prefix);
                std::memcpy(data, &netmask, sizeof(netmask));
            }
            break;

            case LanParam::GATEWAY:
            {
                auto sysObj = ipmi::getDbusObject(
                    bus, ipmi::network::SYSTEMCONFIG_INTERFACE,
                    ipmi::network::ROOT);

                auto gateway = std::get<std::string>(ipmi::getDbusProperty(
                    bus, sysObj.second, sysObj.first,
                    ipmi::network::SYSTEMCONFIG_INTERFACE, "DefaultGateway"));

                inet_pton(AF_INET, gateway.c_str(), data);
            }
            break;

            case LanParam::MAC:
            {
                auto macObj =
                    ipmi::getDbusObject(bus, ipmi::network::MAC_INTERFACE,
                                        ipmi::network::ROOT, ethdevice);
                auto macStr = std::get<std::string>(ipmi::getDbusProperty(
                    bus, macObj.second, macObj.first,
                    ipmi::network::MAC_INTERFACE, "MACAddress"));
                const ether_addr* mac = ether_aton(macStr.c_str());
                if (mac == nullptr)
                {
                    log<level::ERR>("Got a bad MAC from network daemon");
                    elog<InternalFailure>();
                }
                std::memcpy(data, mac, sizeof(*mac));
            }
            break;

            case LanParam::VLAN:
            {
                uint16_t vlan;
                if (!channelConf->vlan)
                {
                    auto ipObjectInfo = ipmi::getIPObject(
                        bus, ipmi::network::IP_INTERFACE, ipmi::network::ROOT,
                        ipmi::network::IP_TYPE);

                    uint32_t ret = ipmi::network::getVLAN(ipObjectInfo.first);
                    if (ret > ipmi::network::VLAN_VALUE_MASK)
                    {
                        log<level::ERR>("DBUS returned an invalid VLAN",
                                        entry("VLAN=%" PRIu32, ret));
                        elog<InternalFailure>();
                    }
                    vlan = ret;
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
        log<level::ERR>(
            "Failed to get network data", entry("PARAMETER=%" PRIu8, lan_param),
            entry("CHANNEL=%d", channel), entry("ERROR=%s", e.what()));
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
    auto ethdevice = ipmi::getChannelName(channel);
    if (ethdevice.empty())
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
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
            ether_addr mac;
            std::memcpy(&mac, reqptr->data, sizeof(mac));
            std::string macStr = ether_ntoa(&mac);
            auto macObj = ipmi::getDbusObject(bus, ipmi::network::MAC_INTERFACE,
                                              ipmi::network::ROOT, ethdevice);
            ipmi::setDbusProperty(bus, macObj.second, macObj.first,
                                  ipmi::network::MAC_INTERFACE, "MACAddress",
                                  macStr);
            return IPMI_CC_OK;
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

    auto ethdevice = ipmi::getChannelName(channel);
    if (ethdevice.empty())
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    auto channelConf = getChannelConfig(channel);

    LanParam param = static_cast<LanParam>(reqptr->parameter);
    switch (param)
    {
        case LanParam::INPROGRESS:
        {
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

void applyChanges(int channel)
{
    std::string ipaddress;
    bool dhcpEnabled{};
    uint8_t prefix = DEFAULT_PREFIX;
    uint16_t vlan{};
    std::string networkInterfacePath;
    ipmi::DbusObjectInfo ipObject;

    auto ethdevice = ipmi::getChannelName(channel);
    if (ethdevice.empty())
    {
        log<level::ERR>("Unable to get the interface name",
                        entry("CHANNEL=%d", channel));
        return;
    }
    auto ethIp = ethdevice + "/" + ipmi::network::IP_TYPE;
    auto channelConf = getChannelConfig(channel);

    try
    {
        sdbusplus::bus::bus bus(ipmid_get_sd_bus_connection());

        if (channelConf->vlan && std::get<bool>(*channelConf->vlan))
        {
            vlan = std::get<uint16_t>(*channelConf->vlan);
        }

        // if the asked ip src is DHCP then not interested in
        // any given data except vlan.
        if (!channelConf->dhcpEnabled.value_or(false))
        {
            // the below code is to determine the mode of the interface
            // as the handling is same, if the system is configured with
            // DHCP or user has given all the data.
            try
            {
                ipmi::ObjectTree ancestorMap;

                ipmi::InterfaceList interfaces{
                    ipmi::network::ETHERNET_INTERFACE};

                // if the system is having ip object,then
                // get the IP object.
                ipObject = ipmi::getIPObject(bus, ipmi::network::IP_INTERFACE,
                                             ipmi::network::ROOT, ethIp);

                // Get the parent interface of the IP object.
                try
                {
                    ancestorMap = ipmi::getAllAncestors(bus, ipObject.first,
                                                        std::move(interfaces));
                }
                catch (InternalFailure& e)
                {
                    // if unable to get the parent interface
                    // then commit the error and return.
                    log<level::ERR>("Unable to get the parent interface",
                                    entry("PATH=%s", ipObject.first.c_str()),
                                    entry("INTERFACE=%s",
                                          ipmi::network::ETHERNET_INTERFACE));
                    commit<InternalFailure>();
                    channelConf->clear();
                    return;
                }

                networkInterfacePath = ancestorMap.begin()->first;
            }
            catch (InternalFailure& e)
            {
                // TODO Currently IPMI supports single interface,need to handle
                // Multiple interface through
                // https://github.com/openbmc/openbmc/issues/2138

                // if there is no ip configured on the system,then
                // get the network interface object.
                auto networkInterfaceObject =
                    ipmi::getDbusObject(bus, ipmi::network::ETHERNET_INTERFACE,
                                        ipmi::network::ROOT, ethdevice);

                networkInterfacePath = std::move(networkInterfaceObject.first);
            }

            // get the configured mode on the system.
            auto currentDHCP = variant_ns::get<bool>(ipmi::getDbusProperty(
                bus, ipmi::network::SERVICE, networkInterfacePath,
                ipmi::network::ETHERNET_INTERFACE, "DHCPEnabled"));

            // if ip address source is not given then get the ip source mode
            // from the system so that it can be applied later.
            dhcpEnabled = channelConf->dhcpEnabled.value_or(currentDHCP);

            // check whether user has given all the data
            // or the configured system interface is dhcp enabled,
            // in both of the cases get the values from the cache.
            if ((!channelConf->ipaddr.empty() && channelConf->prefix) ||
                currentDHCP) // configured system interface mode = DHCP
            {
                // convert mask into prefix
                ipaddress = channelConf->ipaddr;
                prefix = channelConf->prefix.value_or(DEFAULT_PREFIX);
            }
            else // asked ip src = static and configured system src = static
                 // or partially given data.
            {
                // We have partial filled cache so get the remaining
                // info from the system.

                // Get the network data from the system as user has
                // not given all the data then use the data fetched from the
                // system but it is implementation dependent,IPMI spec doesn't
                // force it.

                // if system is not having any ip object don't throw error,
                try
                {
                    auto properties = ipmi::getAllDbusProperties(
                        bus, ipObject.second, ipObject.first,
                        ipmi::network::IP_INTERFACE);

                    ipaddress = channelConf->ipaddr.empty()
                                    ? variant_ns::get<std::string>(
                                          properties["Address"])
                                    : channelConf->ipaddr;

                    prefix = channelConf->prefix.value_or(
                        variant_ns::get<uint8_t>(properties["PrefixLength"]));
                }
                catch (InternalFailure& e)
                {
                    log<level::INFO>(
                        "Failed to get IP object which matches",
                        entry("INTERFACE=%s", ipmi::network::IP_INTERFACE),
                        entry("MATCH=%s", ethIp.c_str()));
                }
            }
        }

        // Currently network manager doesn't support purging of all the
        // ip addresses and the vlan interfaces from the parent interface,
        // TODO once the support is there, will make the change here.
        // https://github.com/openbmc/openbmc/issues/2141.

        // TODO Currently IPMI supports single interface,need to handle
        // Multiple interface through
        // https://github.com/openbmc/openbmc/issues/2138

        // instead of deleting all the vlan interfaces and
        // all the ipv4 address,we will call reset method.
        // delete all the vlan interfaces

        ipmi::deleteAllDbusObjects(bus, ipmi::network::ROOT,
                                   ipmi::network::VLAN_INTERFACE);

        // set the interface mode  to static
        auto networkInterfaceObject =
            ipmi::getDbusObject(bus, ipmi::network::ETHERNET_INTERFACE,
                                ipmi::network::ROOT, ethdevice);

        // setting the physical interface mode to static.
        ipmi::setDbusProperty(
            bus, ipmi::network::SERVICE, networkInterfaceObject.first,
            ipmi::network::ETHERNET_INTERFACE, "DHCPEnabled", false);

        networkInterfacePath = networkInterfaceObject.first;

        // delete all the ipv4 addresses
        ipmi::deleteAllDbusObjects(bus, ipmi::network::ROOT,
                                   ipmi::network::IP_INTERFACE, ethIp);

        if (vlan)
        {
            ipmi::network::createVLAN(bus, ipmi::network::SERVICE,
                                      ipmi::network::ROOT, ethdevice, vlan);

            auto networkInterfaceObject = ipmi::getDbusObject(
                bus, ipmi::network::VLAN_INTERFACE, ipmi::network::ROOT);

            networkInterfacePath = networkInterfaceObject.first;
        }

        if (dhcpEnabled)
        {
            ipmi::setDbusProperty(
                bus, ipmi::network::SERVICE, networkInterfacePath,
                ipmi::network::ETHERNET_INTERFACE, "DHCPEnabled", true);
        }
        else
        {
            // change the mode to static
            ipmi::setDbusProperty(
                bus, ipmi::network::SERVICE, networkInterfacePath,
                ipmi::network::ETHERNET_INTERFACE, "DHCPEnabled", false);

            if (!ipaddress.empty())
            {
                ipmi::network::createIP(bus, ipmi::network::SERVICE,
                                        networkInterfacePath, ipv4Protocol,
                                        ipaddress, prefix);
            }
        }
    }
    catch (sdbusplus::exception::exception& e)
    {
        log<level::ERR>("Failed to set network data",
                        entry("PREFIX=%" PRIu8, prefix),
                        entry("ADDRESS=%s", ipaddress.c_str()),
                        entry("VLANID=%" PRIu16, vlan),
                        entry("DHCP=%s", dhcpEnabled ? "true" : "false"));

        commit<InternalFailure>();
    }

    channelConf->clear();
}

void commitNetworkChanges()
{
    for (const auto& channel : channelConfig)
    {
        if (channel.second->flush)
        {
            applyChanges(channel.first);
        }
    }
}

void createNetworkTimer()
{
    if (!networkTimer)
    {
        std::function<void()> networkTimerCallback(
            std::bind(&commitNetworkChanges));

        networkTimer = std::make_unique<phosphor::Timer>(networkTimerCallback);
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
