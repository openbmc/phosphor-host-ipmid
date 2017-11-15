#include "channel.hpp"
#include "types.hpp"
#include "transporthandler.hpp"
#include "utils.hpp"
#include "net.hpp"

#include <string>
#include <arpa/inet.h>

#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include "xyz/openbmc_project/Common/error.hpp"

extern struct ChannelConfig_t channelConfig[];

constexpr auto ipv4Protocol = "xyz.openbmc_project.Network.IP.Protocol.IPv4";

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

/** @struct GetChannelAccessRequest
 *
 *  IPMI payload for Get Channel access command request.
 */
struct GetChannelAccessRequest
{
    uint8_t channelNumber;      //!< Channel number.
    uint8_t volatileSetting;    //!< Get non-volatile or the volatile setting.
} __attribute__((packed));

/** @struct GetChannelAccessResponse
 *
 *  IPMI payload for Get Channel access command response.
 */
struct GetChannelAccessResponse
{
    uint8_t settings;          //!< Channel settings.
    uint8_t privilegeLimit;    //!< Channel privilege level limit.
} __attribute__((packed));

ipmi_ret_t ipmi_set_channel_access(ipmi_netfn_t netfn,
                                   ipmi_cmd_t cmd,
                                   ipmi_request_t request,
                                   ipmi_response_t response,
                                   ipmi_data_len_t data_len,
                                   ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;

    std::string ipaddress;
    std::string gateway;
    uint8_t prefix {};
    uint32_t vlanID {};
    std::string networkInterfacePath;
    ipmi::DbusObjectInfo ipObject;
    ipmi::DbusObjectInfo systemObject;

    auto requestData = reinterpret_cast<const GetChannelAccessRequest*>
                   (request);
    int channel = requestData->channelNumber & 0x0f;
    std::string ethdevice = ipmi::network::ChanneltoEthernet(channel);
    std::string ethIp = ethdevice + "/" + ipmi::network::IP_TYPE;

    // Todo: parse the request data if needed.
    // Using Set Channel cmd to apply changes of Set Lan Cmd.
    try
    {
        sdbusplus::bus::bus bus(ipmid_get_sd_bus_connection());

        log<level::INFO>("Network data from Cache",
                         entry("PREFIX=%s", channelConfig[channel].netmask.c_str()),
                         entry("ADDRESS=%s", channelConfig[channel].ipaddr.c_str()),
                         entry("GATEWAY=%s", channelConfig[channel].gateway.c_str()),
                         entry("VLAN=%d", channelConfig[channel].vlanID),
                         entry("IPSRC=%d", channelConfig[channel].ipsrc));

        if (channelConfig[channel].vlanID != ipmi::network::VLAN_ID_MASK)
        {
            //get the first twelve bits which is vlan id
            //not interested in rest of the bits.
            channelConfig[channel].vlanID = le32toh(channelConfig[channel].vlanID);
            vlanID = channelConfig[channel].vlanID & ipmi::network::VLAN_ID_MASK;
        }

        // if the asked ip src is DHCP then not interested in
        // any given data except vlan.
        if (channelConfig[channel].ipsrc != ipmi::network::IPOrigin::DHCP)
        {
            // always get the system object
            systemObject = ipmi::getDbusObject(
                    bus,
                    ipmi::network::SYSTEMCONFIG_INTERFACE,
                    ipmi::network::ROOT);

            // the below code is to determine the mode of the interface
            // as the handling is same, if the system is configured with
            // DHCP or user has given all the data.
            try
            {
                ipmi::ObjectTree ancestorMap;

                ipmi::InterfaceList interfaces {
                    ipmi::network::ETHERNET_INTERFACE };

                // if the system is having ip object,then
                // get the IP object.
                ipObject = ipmi::getDbusObject(bus,
                                               ipmi::network::IP_INTERFACE,
                                               ipmi::network::ROOT,
                                               ethIp);

                // Get the parent interface of the IP object.
                try
                {
                    ancestorMap = ipmi::getAllAncestors(bus,
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
                    commit<InternalFailure>();
                    rc = IPMI_CC_UNSPECIFIED_ERROR;
                    channelConfig[channel].clear();
                    return rc;
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
                auto networkInterfaceObject = ipmi::getDbusObject(
                        bus,
                        ipmi::network::ETHERNET_INTERFACE,
                        ipmi::network::ROOT,
                        ethdevice);

                networkInterfacePath = std::move(networkInterfaceObject.first);
            }

            // get the configured mode on the system.
            auto enableDHCP = ipmi::getDbusProperty(
                    bus,
                    ipmi::network::SERVICE,
                    networkInterfacePath,
                    ipmi::network::ETHERNET_INTERFACE,
                    "DHCPEnabled").get<bool>();

            // check whether user has given all the data
            // or the configured system interface is dhcp enabled,
            // in both of the cases get the values from the cache.
            if ((!channelConfig[channel].ipaddr.empty() &&
                 !channelConfig[channel].netmask.empty() &&
                 !channelConfig[channel].gateway.empty()) ||
                (enableDHCP)) // configured system interface mode = DHCP
            {
                //convert mask into prefix
                ipaddress = channelConfig[channel].ipaddr;
                prefix = ipmi::network::toPrefix(AF_INET, channelConfig[channel].netmask);
                gateway = channelConfig[channel].gateway;
                if (channelConfig[channel].vlanID != ipmi::network::VLAN_ID_MASK)
                {
                    //get the first twelve bits which is vlan id
                    //not interested in rest of the bits.
                    channelConfig[channel].vlanID = le32toh(channelConfig[channel].vlanID);
                    vlanID = channelConfig[channel].vlanID & ipmi::network::VLAN_ID_MASK;
                }
                else
                {
                    vlanID = ipmi::network::getVLAN(networkInterfacePath);
                }

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
                            bus,
                            ipObject.second,
                            ipObject.first,
                            ipmi::network::IP_INTERFACE);

                    ipaddress = channelConfig[channel].ipaddr.empty() ?
                                ipmi::getIPAddress(bus,
                                                   ipmi::network::IP_INTERFACE,
                                                   ipmi::network::ROOT,
                                                   ethIp) :
                                channelConfig[channel].ipaddr;

                    prefix = channelConfig[channel].netmask.empty() ?
                        properties["PrefixLength"].get<uint8_t>() :
                        ipmi::network::toPrefix(AF_INET,
                                channelConfig[channel].netmask);
                }
                catch (InternalFailure& e)
                {
                    log<level::INFO>("Failed to get IP object which matches",
                            entry("INTERFACE=%s", ipmi::network::IP_INTERFACE),
                            entry("MATCH=%s", ethIp));
                }

                auto systemProperties = ipmi::getAllDbusProperties(
                        bus,
                        systemObject.second,
                        systemObject.first,
                        ipmi::network::SYSTEMCONFIG_INTERFACE);

                gateway = channelConfig[channel].gateway.empty() ?
                        systemProperties["DefaultGateway"].get<std::string>() :
                        channelConfig[channel].gateway;
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
        //delete all the vlan interfaces

        ipmi::deleteAllDbusObjects(bus,
                                   ipmi::network::ROOT,
                                   ipmi::network::VLAN_INTERFACE);

        // set the interface mode  to static
        auto networkInterfaceObject = ipmi::getDbusObject(
                bus,
                ipmi::network::ETHERNET_INTERFACE,
                ipmi::network::ROOT,
                ethdevice);

        // setting the physical interface mode to static.
        ipmi::setDbusProperty(bus,
                              ipmi::network::SERVICE,
                              networkInterfaceObject.first,
                              ipmi::network::ETHERNET_INTERFACE,
                              "DHCPEnabled",
                              false);

        networkInterfacePath = networkInterfaceObject.first;

        //delete all the ipv4 addresses
        ipmi::deleteAllDbusObjects(bus,
                                   ipmi::network::ROOT,
                                   ipmi::network::IP_INTERFACE,
                                   ethIp);

        if (vlanID)
        {
            ipmi::network::createVLAN(bus,
                                      ipmi::network::SERVICE,
                                      ipmi::network::ROOT,
                                      ethdevice,
                                      vlanID);

            auto networkInterfaceObject = ipmi::getDbusObject(
                    bus,
                    ipmi::network::VLAN_INTERFACE,
                    ipmi::network::ROOT);

           networkInterfacePath = networkInterfaceObject.first;
        }

        if (channelConfig[channel].ipsrc == ipmi::network::IPOrigin::DHCP)
        {
            ipmi::setDbusProperty(bus,
                                  ipmi::network::SERVICE,
                                  networkInterfacePath,
                                  ipmi::network::ETHERNET_INTERFACE,
                                  "DHCPEnabled",
                                  true);
        }
        else
        {
            //change the mode to static
            ipmi::setDbusProperty(bus,
                                  ipmi::network::SERVICE,
                                  networkInterfacePath,
                                  ipmi::network::ETHERNET_INTERFACE,
                                  "DHCPEnabled",
                                  false);

            // TODO(venture): Prefix must be set too!
            if (!ipaddress.empty())
            {
                ipmi::network::createIP(bus,
                                        ipmi::network::SERVICE,
                                        networkInterfacePath,
                                        ipv4Protocol,
                                        ipaddress,
                                        prefix);
            }

            if (!gateway.empty())
            {
                ipmi::setDbusProperty(bus,
                                      systemObject.second,
                                      systemObject.first,
                                      ipmi::network::SYSTEMCONFIG_INTERFACE,
                                      "DefaultGateway",
                                      std::string(gateway));
            }
        }

    }
    catch (InternalFailure& e)
    {
        log<level::ERR>("Failed to set network data",
                        entry("PREFIX=%d", prefix),
                        entry("ADDRESS=%s", ipaddress.c_str()),
                        entry("GATEWAY=%s", gateway.c_str()),
                        entry("VLANID=%d", vlanID),
                        entry("IPSRC=%d", channelConfig[channel].ipsrc));

        commit<InternalFailure>();
        rc = IPMI_CC_UNSPECIFIED_ERROR;
    }

    channelConfig[channel].clear();
    return rc;
}

ipmi_ret_t ipmi_get_channel_access(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                            ipmi_request_t request, ipmi_response_t response,
                            ipmi_data_len_t data_len, ipmi_context_t context)
{
    auto requestData = reinterpret_cast<const GetChannelAccessRequest*>
                   (request);
    std::vector<uint8_t> outPayload(sizeof(GetChannelAccessResponse));
    auto responseData = reinterpret_cast<GetChannelAccessResponse*>
            (outPayload.data());

    /*
     * The value Eh is used as a way to identify the current channel that
     * the command is being received from.
     */
    constexpr auto channelE = 0x0E;
    int channel = requestData->channelNumber;
    std::string ethdevice = ipmi::network::ChanneltoEthernet(channel);

    if (channel != channelE && ethdevice.empty())
    {
        *data_len = 0;
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    /*
     * [7:6] - reserved
     * [5]   - 1b = Alerting disabled
     * [4]   - 1b = per message authentication disabled
     * [3]   - 0b = User level authentication enabled
     * [2:0] - 2h = always available
     */
    constexpr auto channelSetting = 0x32;

    responseData->settings = channelSetting;
    //Defaulting the channel privilege to administrator level.
    responseData->privilegeLimit = PRIVILEGE_ADMIN;

    *data_len = outPayload.size();
    memcpy(response, outPayload.data(), *data_len);

    return IPMI_CC_OK;
}

// ATTENTION: This ipmi function is very hardcoded on purpose
// OpenBMC does not fully support IPMI.  This command is useful
// to have around because it enables testing of interfaces with
// the IPMI tool.
#define GET_CHANNEL_INFO_CHANNEL_OFFSET 0
// IPMI Table 6-2
#define IPMI_CHANNEL_TYPE_IPMB 1
// IPMI Table 6-3
#define IPMI_CHANNEL_MEDIUM_TYPE_OTHER 6

ipmi_ret_t ipmi_app_channel_info(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    uint8_t resp[] = {
        1,
        IPMI_CHANNEL_MEDIUM_TYPE_OTHER,
        IPMI_CHANNEL_TYPE_IPMB,
        1,0x41,0xA7,0x00,0,0};
    uint8_t *p = (uint8_t*) request;
    int channel = (*p) & 0x0f;
    std::string ethdevice = ipmi::network::ChanneltoEthernet(channel);

    printf("IPMI APP GET CHANNEL INFO\n");

    // The supported channels numbers are those which are configured.
    // Channel Number E is used as way to identify the current channel
    // that the command is being is received from.
    if (channel != 0xe && ethdevice.empty()) {
        rc = IPMI_CC_PARM_OUT_OF_RANGE;
        *data_len = 0;
    } else {
        *data_len = sizeof(resp);
        memcpy(response, resp, *data_len);
    }

    return rc;
}
