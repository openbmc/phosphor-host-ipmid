#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string>
#include <experimental/filesystem>

#include "host-ipmid/ipmid-api.h"
#include "ipmid.hpp"
#include "transporthandler.hpp"
#include "utils.hpp"
#include "net.hpp"

#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include "xyz/openbmc_project/Common/error.hpp"

#define SYSTEMD_NETWORKD_DBUS 1

#ifdef SYSTEMD_NETWORKD_DBUS
#include <systemd/sd-bus.h>
#include <mapper.h>
#endif

const int SIZE_MAC = 18; //xx:xx:xx:xx:xx:xx

std::map<int, std::unique_ptr<struct ChannelConfig_t>> channelConfig;

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
namespace fs = std::experimental::filesystem;

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

// Helper Function to get IP Address/NetMask/Gateway/MAC Address from Network Manager or
// Cache based on Set-In-Progress State
ipmi_ret_t getNetworkData(uint8_t lan_param, uint8_t* data, int channel)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    sdbusplus::bus::bus bus(ipmid_get_sd_bus_connection());

    std::string ethdevice = ipmi::network::ChanneltoEthernet(channel);
    // if ethdevice is an empty string they weren't expecting this channel.
    if (ethdevice.empty())
    {
        // TODO: return error from getNetworkData()
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    std::string ethIP = ethdevice + "/" + ipmi::network::IP_TYPE;
    auto channelConf = getChannelConfig(channel);

    try
    {
        switch (lan_param)
        {
            case LAN_PARM_IP:
            {
                std::string ipaddress;
                if (channelConf->lan_set_in_progress == SET_COMPLETE)
                {
                    try
                    {
                        ipaddress = ipmi::getIPAddress(bus,
                                                       ipmi::network::IP_INTERFACE,
                                                       ipmi::network::ROOT,
                                                       ethIP);

                    }
                    // ignore the exception, as it is a valid condtion that
                    // system is not confiured with any ip.
                    catch (InternalFailure& e)
                    {
                        // nothing to do.
                    }
                }
                else if (channelConf->lan_set_in_progress == SET_IN_PROGRESS)
                {
                    ipaddress = channelConf->ipaddr;
                }

                inet_pton(AF_INET, ipaddress.c_str(),
                          reinterpret_cast<void*>(data));
            }
            break;

            case LAN_PARM_IPSRC:
            {
                std::string networkInterfacePath;

                if (channelConf->lan_set_in_progress == SET_COMPLETE)
                {
                    try
                    {
                        ipmi::ObjectTree ancestorMap;
                        // if the system is having ip object,then
                        // get the IP object.
                        auto ipObject = ipmi::getDbusObject(
                                bus,
                                ipmi::network::IP_INTERFACE,
                                ipmi::network::ROOT,
                                ethIP);

                        // Get the parent interface of the IP object.
                        try
                        {
                            ipmi::InterfaceList interfaces;
                            interfaces.emplace_back(
                                    ipmi::network::ETHERNET_INTERFACE);

                            ancestorMap = ipmi::getAllAncestors(
                                    bus,
                                    ipObject.first,
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
                            break;

                        }
                        // for an ip object there would be single parent
                        // interface.
                        networkInterfacePath = ancestorMap.begin()->first;
                    }
                    catch (InternalFailure& e)
                    {
                        // if there is no ip configured on the system,then
                        // get the network interface object.
                        auto networkInterfaceObject = ipmi::getDbusObject(
                                bus,
                                ipmi::network::ETHERNET_INTERFACE,
                                ipmi::network::ROOT,
                                ethdevice);

                        networkInterfacePath = networkInterfaceObject.first;
                    }

                    auto variant = ipmi::getDbusProperty(
                            bus,
                            ipmi::network::SERVICE,
                            networkInterfacePath,
                            ipmi::network::ETHERNET_INTERFACE,
                            "DHCPEnabled");

                    auto dhcpEnabled = variant.get<bool>();
                    // As per IPMI spec 2=>DHCP, 1=STATIC
                    auto ipsrc = dhcpEnabled ? ipmi::network::IPOrigin::DHCP :
                                               ipmi::network::IPOrigin::STATIC;

                    memcpy(data, &ipsrc, ipmi::network::IPSRC_SIZE_BYTE);
                }
                else if (channelConf->lan_set_in_progress == SET_IN_PROGRESS)
                {
                   memcpy(data, &(channelConf->ipsrc),
                          ipmi::network::IPSRC_SIZE_BYTE);
                }
            }
            break;

            case LAN_PARM_SUBNET:
            {
                unsigned long mask {};
                if (channelConf->lan_set_in_progress == SET_COMPLETE)
                {
                    try
                    {
                        auto ipObjectInfo = ipmi::getDbusObject(
                                bus,
                                ipmi::network::IP_INTERFACE,
                                ipmi::network::ROOT,
                                ipmi::network::IP_TYPE);

                        auto properties = ipmi::getAllDbusProperties(
                                bus,
                                ipObjectInfo.second,
                                ipObjectInfo.first,
                                ipmi::network::IP_INTERFACE);

                        auto prefix = properties["PrefixLength"].get<uint8_t>();
                        mask = ipmi::network::MASK_32_BIT;
                        mask = htonl(mask << (ipmi::network::BITS_32 - prefix));
                    }
                    // ignore the exception, as it is a valid condtion that
                    // system is not confiured with any ip.
                    catch (InternalFailure& e)
                    {
                        // nothing to do
                    }
                    memcpy(data, &mask, ipmi::network::IPV4_ADDRESS_SIZE_BYTE);
                }
                else if (channelConf->lan_set_in_progress == SET_IN_PROGRESS)
                {
                    inet_pton(AF_INET, channelConf->netmask.c_str(),
                              reinterpret_cast<void*>(data));
                }

            }
            break;

            case LAN_PARM_GATEWAY:
            {
                std::string gateway;

                if (channelConf->lan_set_in_progress == SET_COMPLETE)
                {
                    try
                    {
                        auto systemObject = ipmi::getDbusObject(
                                bus,
                                ipmi::network::SYSTEMCONFIG_INTERFACE,
                                ipmi::network::ROOT);

                        auto systemProperties = ipmi::getAllDbusProperties(
                                bus,
                                systemObject.second,
                                systemObject.first,
                                ipmi::network::SYSTEMCONFIG_INTERFACE);

                        gateway = systemProperties["DefaultGateway"].get<
                            std::string>();
                    }
                    // ignore the exception, as it is a valid condtion that
                    // system is not confiured with any ip.
                    catch (InternalFailure& e)
                    {
                        // nothing to do
                    }

                }
                else if (channelConf->lan_set_in_progress == SET_IN_PROGRESS)
                {
                    gateway = channelConf->gateway;
                }

                inet_pton(AF_INET, gateway.c_str(),
                          reinterpret_cast<void*>(data));
            }
            break;

            case LAN_PARM_MAC:
            {
                std::string macAddress;
                if (channelConf->lan_set_in_progress == SET_COMPLETE)
                {
                    auto macObjectInfo = ipmi::getDbusObject(
                                             bus,
                                             ipmi::network::MAC_INTERFACE,
                                             ipmi::network::ROOT,
                                             ethdevice);

                    auto variant = ipmi::getDbusProperty(
                                     bus,
                                     macObjectInfo.second,
                                     macObjectInfo.first,
                                     ipmi::network::MAC_INTERFACE,
                                     "MACAddress");

                    macAddress = variant.get<std::string>();

                }
                else if (channelConf->lan_set_in_progress == SET_IN_PROGRESS)
                {
                    macAddress = channelConf->macAddress;
                }

                sscanf(macAddress.c_str(), ipmi::network::MAC_ADDRESS_FORMAT,
                       (data),
                       (data + 1),
                       (data + 2),
                       (data + 3),
                       (data + 4),
                       (data + 5));
            }
            break;

            case LAN_PARM_VLAN:
            {
                uint16_t vlanID {};
                if (channelConf->lan_set_in_progress == SET_COMPLETE)
                {
                    try
                    {
                        auto ipObjectInfo = ipmi::getDbusObject(
                                bus,
                                ipmi::network::IP_INTERFACE,
                                ipmi::network::ROOT,
                                ipmi::network::IP_TYPE);

                        vlanID = static_cast<uint16_t>(
                                ipmi::network::getVLAN(ipObjectInfo.first));

                        vlanID = htole16(vlanID);

                        if (vlanID)
                        {
                            //Enable the 16th bit
                            vlanID |= htole16(ipmi::network::VLAN_ENABLE_MASK);
                        }
                    }
                    // ignore the exception, as it is a valid condtion that
                    // system is not confiured with any ip.
                    catch (InternalFailure& e)
                    {
                        // nothing to do
                    }

                    memcpy(data, &vlanID, ipmi::network::VLAN_SIZE_BYTE);
                }
                else if (channelConf->lan_set_in_progress == SET_IN_PROGRESS)
                {
                    memcpy(data, &(channelConf->vlanID),
                           ipmi::network::VLAN_SIZE_BYTE);
                }
            }
            break;

            default:
                rc = IPMI_CC_PARM_OUT_OF_RANGE;
        }
    }
    catch (InternalFailure& e)
    {
        commit<InternalFailure>();
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        return rc;
    }
    return rc;
}

ipmi_ret_t ipmi_transport_wildcard(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    printf("Handling TRANSPORT WILDCARD Netfn:[0x%X], Cmd:[0x%X]\n",netfn, cmd);
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
}  __attribute__((packed));

ipmi_ret_t ipmi_transport_set_lan(ipmi_netfn_t netfn,
                                  ipmi_cmd_t cmd,
                                  ipmi_request_t request,
                                  ipmi_response_t response,
                                  ipmi_data_len_t data_len,
                                  ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;

    char ipaddr[INET_ADDRSTRLEN];
    char netmask[INET_ADDRSTRLEN];
    char gateway[INET_ADDRSTRLEN];

    auto reqptr = reinterpret_cast<const set_lan_t*>(request);
    sdbusplus::bus::bus bus(ipmid_get_sd_bus_connection());

    // channel number is the lower nibble
    int channel = reqptr->channel & CHANNEL_MASK;
    std::string ethdevice = ipmi::network::ChanneltoEthernet(channel);
    if (ethdevice.empty())
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    auto channelConf = getChannelConfig(channel);

    switch (reqptr->parameter)
    {
        case LAN_PARM_IP:
        {
            snprintf(ipaddr, INET_ADDRSTRLEN, ipmi::network::IP_ADDRESS_FORMAT,
                     reqptr->data[0], reqptr->data[1],
                     reqptr->data[2], reqptr->data[3]);

            channelConf->ipaddr.assign(ipaddr);
        }
        break;

        case LAN_PARM_IPSRC:
        {
            uint8_t ipsrc{};
            memcpy(&ipsrc, reqptr->data, ipmi::network::IPSRC_SIZE_BYTE);
            channelConf->ipsrc = static_cast<ipmi::network::IPOrigin>(ipsrc);
        }
        break;

        case LAN_PARM_MAC:
        {
            char mac[SIZE_MAC];

            snprintf(mac, SIZE_MAC, ipmi::network::MAC_ADDRESS_FORMAT,
                     reqptr->data[0],
                     reqptr->data[1],
                     reqptr->data[2],
                     reqptr->data[3],
                     reqptr->data[4],
                     reqptr->data[5]);

            auto macObjectInfo = ipmi::getDbusObject(
                                     bus,
                                     ipmi::network::MAC_INTERFACE,
                                     ipmi::network::ROOT,
                                     ethdevice);

            ipmi::setDbusProperty(bus,
                                  macObjectInfo.second,
                                  macObjectInfo.first,
                                  ipmi::network::MAC_INTERFACE,
                                  "MACAddress",
                                  std::string(mac));

            channelConf->macAddress = mac;
        }
        break;

        case LAN_PARM_SUBNET:
        {
            snprintf(netmask, INET_ADDRSTRLEN, ipmi::network::IP_ADDRESS_FORMAT,
                     reqptr->data[0], reqptr->data[1],
                     reqptr->data[2], reqptr->data[3]);
            channelConf->netmask.assign(netmask);
        }
        break;

        case LAN_PARM_GATEWAY:
        {
            snprintf(gateway, INET_ADDRSTRLEN, ipmi::network::IP_ADDRESS_FORMAT,
                     reqptr->data[0], reqptr->data[1],
                     reqptr->data[2], reqptr->data[3]);
            channelConf->gateway.assign(gateway);
        }
        break;

        case LAN_PARM_VLAN:
        {
            uint16_t vlan {};
            memcpy(&vlan, reqptr->data, ipmi::network::VLAN_SIZE_BYTE);
            // We are not storing the enable bit
            // We assume that ipmitool always send enable
            // bit as 1.
            vlan = le16toh(vlan);
            channelConf->vlanID = vlan;
        }
        break;

        case LAN_PARM_INPROGRESS:
        {
            if (reqptr->data[0] == SET_COMPLETE)
            {
                channelConf->lan_set_in_progress = SET_COMPLETE;

                log<level::INFO>("Network data from Cache",
                                 entry("PREFIX=%s", channelConf->netmask.c_str()),
                                 entry("ADDRESS=%s", channelConf->ipaddr.c_str()),
                                 entry("GATEWAY=%s", channelConf->gateway.c_str()),
                                 entry("VLAN=%d", channelConf->vlanID));

                log<level::INFO>("Use Set Channel Access command to apply");
            }
            else if (reqptr->data[0] == SET_IN_PROGRESS) // Set In Progress
            {
                channelConf->lan_set_in_progress = SET_IN_PROGRESS;
            }
        }
        break;

        default:
        {
            rc = IPMI_CC_PARM_NOT_SUPPORTED;
        }
    }

    return rc;
}

struct get_lan_t
{
    uint8_t rev_channel;
    uint8_t parameter;
    uint8_t parameter_set;
    uint8_t parameter_block;
}  __attribute__((packed));

ipmi_ret_t ipmi_transport_get_lan(ipmi_netfn_t netfn,
                                  ipmi_cmd_t cmd,
                                  ipmi_request_t request,
                                  ipmi_response_t response,
                                  ipmi_data_len_t data_len,
                                  ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;
    const uint8_t current_revision = 0x11; // Current rev per IPMI Spec 2.0

    get_lan_t *reqptr = (get_lan_t*) request;
    // channel number is the lower nibble
    int channel = reqptr->rev_channel & CHANNEL_MASK;

    if (reqptr->rev_channel & 0x80) // Revision is bit 7
    {
        // Only current revision was requested
        *data_len = sizeof(current_revision);
        memcpy(response, &current_revision, *data_len);
        return IPMI_CC_OK;
    }

    std::string ethdevice = ipmi::network::ChanneltoEthernet(channel);
    if (ethdevice.empty())
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    auto channelConf = getChannelConfig(channel);

    if (reqptr->parameter == LAN_PARM_INPROGRESS)
    {
        uint8_t buf[] = {current_revision, channelConf->lan_set_in_progress};
        *data_len = sizeof(buf);
        memcpy(response, &buf, *data_len);
    }
    else if (reqptr->parameter == LAN_PARM_AUTHSUPPORT)
    {
        uint8_t buf[] = {current_revision,0x04};
        *data_len = sizeof(buf);
        memcpy(response, &buf, *data_len);
    }
    else if (reqptr->parameter == LAN_PARM_AUTHENABLES)
    {
        uint8_t buf[] = {current_revision,0x04,0x04,0x04,0x04,0x04};
        *data_len = sizeof(buf);
        memcpy(response, &buf, *data_len);
    }
    else if ((reqptr->parameter == LAN_PARM_IP) ||
             (reqptr->parameter == LAN_PARM_SUBNET) ||
             (reqptr->parameter == LAN_PARM_GATEWAY) ||
             (reqptr->parameter == LAN_PARM_MAC))
    {
        uint8_t buf[ipmi::network::MAC_ADDRESS_SIZE_BYTE + 1] = {};

        *data_len = sizeof(current_revision);
        memcpy(buf, &current_revision, *data_len);

        if (getNetworkData(reqptr->parameter, &buf[1], channel) == IPMI_CC_OK)
        {
            if (reqptr->parameter == LAN_PARM_MAC)
            {
                *data_len = sizeof(buf);
            }
            else
            {
                *data_len = ipmi::network::IPV4_ADDRESS_SIZE_BYTE + 1;
            }
            memcpy(response, &buf, *data_len);
        }
        else
        {
            rc = IPMI_CC_UNSPECIFIED_ERROR;
        }
    }
    else if (reqptr->parameter == LAN_PARM_VLAN)
    {
        uint8_t buf[ipmi::network::VLAN_SIZE_BYTE + 1] = {};

        *data_len = sizeof(current_revision);
        memcpy(buf, &current_revision, *data_len);
        if (getNetworkData(reqptr->parameter, &buf[1], channel) == IPMI_CC_OK)
        {
            *data_len = sizeof(buf);
            memcpy(response, &buf, *data_len);
        }
    }
    else if (reqptr->parameter == LAN_PARM_IPSRC)
    {
        uint8_t buff[ipmi::network::IPSRC_SIZE_BYTE + 1] = {};
        *data_len = sizeof(current_revision);
        memcpy(buff, &current_revision, *data_len);
        if (getNetworkData(reqptr->parameter, &buff[1], channel) == IPMI_CC_OK)
        {
            *data_len = sizeof(buff);
            memcpy(response, &buff, *data_len);
        }
    }
    else
    {
        log<level::ERR>("Unsupported parameter",
                        entry("PARAMETER=0x%x", reqptr->parameter));
        rc = IPMI_CC_PARM_NOT_SUPPORTED;
    }

    return rc;
}

void register_netfn_transport_functions()
{
    // <Wildcard Command>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_TRANSPORT, IPMI_CMD_WILDCARD);
    ipmi_register_callback(NETFUN_TRANSPORT, IPMI_CMD_WILDCARD, NULL, ipmi_transport_wildcard,
                           PRIVILEGE_USER);

    // <Set LAN Configuration Parameters>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_TRANSPORT, IPMI_CMD_SET_LAN);
    ipmi_register_callback(NETFUN_TRANSPORT, IPMI_CMD_SET_LAN, NULL, ipmi_transport_set_lan,
                           PRIVILEGE_ADMIN);

    // <Get LAN Configuration Parameters>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_TRANSPORT, IPMI_CMD_GET_LAN);
    ipmi_register_callback(NETFUN_TRANSPORT, IPMI_CMD_GET_LAN, NULL, ipmi_transport_get_lan,
                           PRIVILEGE_OPERATOR);

    return;
}
