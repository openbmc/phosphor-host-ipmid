#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string>

#include "host-ipmid/ipmid-api.h"
#include "ipmid.hpp"
#include "transporthandler.h"
#include "utils.hpp"

#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include "xyz/openbmc_project/Common/error.hpp"

#define SYSTEMD_NETWORKD_DBUS 1

#ifdef SYSTEMD_NETWORKD_DBUS
#include <systemd/sd-bus.h>
#include <mapper.h>
#endif

// OpenBMC System Manager dbus framework
const char  *obj   =  "/org/openbmc/NetworkManager/Interface";
const char  *ifc   =  "org.openbmc.NetworkManager";

const char *nwinterface = "eth0";

const int SIZE_MAC = 18; //xx:xx:xx:xx:xx:xx

struct ChannelConfig_t channelConfig;

const uint8_t SET_COMPLETE = 0;
const uint8_t SET_IN_PROGRESS = 1;
const uint8_t SET_COMMIT_WRITE = 2; //Optional
const uint8_t SET_IN_PROGRESS_RESERVED = 3; //Reserved

constexpr auto MAC_ADDRESS_FORMAT = "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx";
constexpr auto IP_ADDRESS_FORMAT = "%d.%d.%d.%d";
constexpr auto NETWORK_MATCH = "eth0/ipv4";
// Status of Set-In-Progress Parameter (# 0)
uint8_t lan_set_in_progress = SET_COMPLETE;

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

void register_netfn_transport_functions() __attribute__((constructor));

// Helper Function to get IP Address/NetMask/Gateway from Network Manager or
// Cache based on Set-In-Progress State
ipmi_ret_t getNetworkData(uint8_t lan_param, uint8_t * data)
{
    ipmi_ret_t rc = IPMI_CC_OK;

    try
    {
        ipmi::PropertyMap properties {};
        ipmi::PropertyMap systemProperties {};

        auto ipObjectInfo = ipmi::getDbusObject(ipmi::IP_INTERFACE,
                ipmi::NETWORK_ROOT,
                NETWORK_MATCH);

        auto macObjectInfo = ipmi::getDbusObject(ipmi::MAC_INTERFACE,
                ipmi::NETWORK_ROOT,
                "eth0");

        auto systemObject = ipmi::getDbusObject(ipmi::SYSTEMCONFIG_INTERFACE,
                ipmi::NETWORK_ROOT);

        properties = ipmi::getAllDbusProperties(ipObjectInfo.second,
                ipObjectInfo.first, ipmi::IP_INTERFACE);

        systemProperties = ipmi::getAllDbusProperties(systemObject.second,
                systemObject.first,
                ipmi::SYSTEMCONFIG_INTERFACE);
        auto macAddress =
            ipmi::getDbusProperty(macObjectInfo.second, macObjectInfo.first,
                    ipmi::MAC_INTERFACE, "MACAddress");

        auto ipaddress = properties["Address"].get<std::string>();
        auto prefix = properties["PrefixLength"].get<uint8_t>();
        auto gateway = systemProperties["DefaultGateway"].get<std::string>();


        unsigned long mask = 0xFFFFFFFF;

        log<level::INFO>("Network data from HW",
                entry("PREFIX=%d", prefix),
                entry("ADDRESS=%s", ipaddress.c_str()),
                entry("GATEWAY=%s", gateway.c_str()),
                entry("MACADDRESS=%s", macAddress.c_str()));

        log<level::INFO>("Network data from Cache",
                entry("PREFIX=%s", channelConfig.netmask.c_str()),
                entry("ADDRESS=%s", channelConfig.ipaddr.c_str()),
                entry("GATEWAY=%s", channelConfig.gateway.c_str()),
                entry("MACADDRESS=%s", channelConfig.macAddress.c_str()));


        switch (lan_param)
        {
            case LAN_PARM_IP:
                {
                    if(lan_set_in_progress == SET_COMPLETE)
                    {
                        inet_pton(AF_INET, ipaddress.c_str(),(void *)data);
                    }
                    else if(lan_set_in_progress == SET_IN_PROGRESS)
                    {
                        inet_pton(AF_INET, channelConfig.ipaddr.c_str(), (void *)data);
                    }
                }
                break;
            case LAN_PARM_SUBNET:
                {
                    if(lan_set_in_progress == SET_COMPLETE)
                    {
                        mask = htonl(mask<<(32-prefix));
                        memcpy(data, &mask, 4);
                    }
                    else if(lan_set_in_progress == SET_IN_PROGRESS)
                    {
                        inet_pton(AF_INET, channelConfig.netmask.c_str(), (void *)data);
                    }

                }
                break;
            case LAN_PARM_GATEWAY:
                {
                    if(lan_set_in_progress == SET_COMPLETE)
                    {
                        inet_pton(AF_INET, gateway.c_str(), (void *)data);
                    }
                    else if(lan_set_in_progress == SET_IN_PROGRESS)
                    {
                        inet_pton(AF_INET, channelConfig.gateway.c_str(),(void *)data);
                    }

                }
                break;
            case LAN_PARM_MAC:
                {
                    if(lan_set_in_progress == SET_COMPLETE)
                    {
                        sscanf(macAddress.c_str(), MAC_ADDRESS_FORMAT,
                                (data),
                                (data + 1),
                                (data + 2),
                                (data + 3),
                                (data + 4),
                                (data + 5));
                    }
                    else if(lan_set_in_progress == SET_IN_PROGRESS)
                    {
                        sscanf(channelConfig.macAddress.c_str(), MAC_ADDRESS_FORMAT,
                                (data),
                                (data + 1),
                                (data + 2),
                                (data + 3),
                                (data + 4),
                                (data + 5));
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

struct set_lan_t {
    uint8_t channel;
    uint8_t parameter;
    uint8_t data[8]; // Per IPMI spec, not expecting more than this size
}  __attribute__ ((packed));

ipmi_ret_t ipmi_transport_set_lan(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;

    char ipaddr[INET_ADDRSTRLEN];
    char netmask[INET_ADDRSTRLEN];
    char gateway[INET_ADDRSTRLEN];

    log<level::INFO>("IPMI SET_LAN");

    set_lan_t *reqptr = (set_lan_t*) request;

    if (reqptr->parameter == LAN_PARM_IP)
    {
        snprintf(ipaddr, INET_ADDRSTRLEN, IP_ADDRESS_FORMAT,
                 reqptr->data[0], reqptr->data[1],
                 reqptr->data[2], reqptr->data[3]);

        channelConfig.ipaddr.assign(ipaddr);

    }
    else if (reqptr->parameter == LAN_PARM_MAC)
    {
        char mac[SIZE_MAC];

        snprintf(mac, SIZE_MAC, "%02x:%02x:%02x:%02x:%02x:%02x",
                reqptr->data[0],
                reqptr->data[1],
                reqptr->data[2],
                reqptr->data[3],
                reqptr->data[4],
                reqptr->data[5]);

        auto macObjectInfo = ipmi::getDbusObject(ipmi::MAC_INTERFACE,
                                                 ipmi::NETWORK_ROOT, "eth0");

        ipmi::setDbusProperty(macObjectInfo.second, macObjectInfo.first,
                              ipmi::MAC_INTERFACE,"MACAddress", std::string(mac));

    } else if (reqptr->parameter == LAN_PARM_SUBNET)
    {
        snprintf(netmask, INET_ADDRSTRLEN, IP_ADDRESS_FORMAT,
                 reqptr->data[0], reqptr->data[1],
                 reqptr->data[2], reqptr->data[3]);
        channelConfig.netmask.assign(netmask);

    } else if (reqptr->parameter == LAN_PARM_GATEWAY)
    {
        snprintf(gateway, INET_ADDRSTRLEN, IP_ADDRESS_FORMAT,
                 reqptr->data[0], reqptr->data[1],
                 reqptr->data[2], reqptr->data[3]);
        channelConfig.gateway.assign(gateway);

    } else if (reqptr->parameter == LAN_PARM_INPROGRESS)
    {
        if(reqptr->data[0] == SET_COMPLETE)
         {
            lan_set_in_progress = SET_COMPLETE;

            log<level::INFO>("Network data from Cache",
                             entry("PREFIX=%s", channelConfig.netmask.c_str()),
                             entry("ADDRESS=%s", channelConfig.ipaddr.c_str()),
                             entry("GATEWAY=%s", channelConfig.gateway.c_str()));
            log<level::INFO>("Use Set Channel Access command to apply them");

        } else if(reqptr->data[0] == SET_IN_PROGRESS) // Set In Progress
        {
            lan_set_in_progress = SET_IN_PROGRESS;
        }
    } else
    {
        log<level::ERR>("Unsupported parameter",
                        entry("PARAMETER=0x%x", reqptr->parameter));
        rc = IPMI_CC_PARM_NOT_SUPPORTED;
    }

    return rc;
}

struct get_lan_t {
    uint8_t rev_channel;
    uint8_t parameter;
    uint8_t parameter_set;
    uint8_t parameter_block;
}  __attribute__ ((packed));

ipmi_ret_t ipmi_transport_get_lan(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;
    const uint8_t current_revision = 0x11; // Current rev per IPMI Spec 2.0

    printf("IPMI GET_LAN\n");

    get_lan_t *reqptr = (get_lan_t*) request;

    if (reqptr->rev_channel & 0x80) // Revision is bit 7
    {
        // Only current revision was requested
        *data_len = sizeof(current_revision);
        memcpy(response, &current_revision, *data_len);
        return IPMI_CC_OK;
    }

    // TODO Use dbus interface once available. For now use ip cmd.
    // TODO Add the rest of the parameters, like gateway

    if (reqptr->parameter == LAN_PARM_INPROGRESS)
    {
        uint8_t buf[] = {current_revision, lan_set_in_progress};
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
        uint8_t buf[7];

        *data_len = sizeof(current_revision);
        memcpy(buf, &current_revision, *data_len);

        if(getNetworkData(reqptr->parameter, &buf[1]) == IPMI_CC_OK)
        {
            *data_len = sizeof(buf);
            memcpy(response, &buf, *data_len);
        }
        else
        {
            rc = IPMI_CC_UNSPECIFIED_ERROR;
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
