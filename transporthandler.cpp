#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string>

#include "host-ipmid/ipmid-api.h"
#include "ipmid.hpp"
#include "transporthandler.h"

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

struct channel_config_t channel_config;

const uint8_t SET_COMPLETE = 0;
const uint8_t SET_IN_PROGRESS = 1;
const uint8_t SET_COMMIT_WRITE = 2; //Optional
const uint8_t SET_IN_PROGRESS_RESERVED = 3; //Reserved

// Status of Set-In-Progress Parameter (# 0)
uint8_t lan_set_in_progress = SET_COMPLETE;



void register_netfn_transport_functions() __attribute__((constructor));

// Helper Function to get IP Address/NetMask/Gateway from Network Manager or
// Cache based on Set-In-Progress State
ipmi_ret_t getNetworkData(uint8_t lan_param, uint8_t * data)
{
    sd_bus *bus = ipmid_get_sd_bus_connection();
    sd_bus_message *reply = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int family;
    unsigned char prefixlen;
    char* ipaddr = NULL;
    unsigned long mask = 0xFFFFFFFF;
    char* gateway = NULL;
    int r = 0;
    ipmi_ret_t rc = IPMI_CC_OK;
    char *app = NULL;

    r = mapper_get_service(bus, obj, &app);
    if (r < 0) {
        fprintf(stderr, "Failed to get %s bus name: %s\n",
                obj, strerror(-r));
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        goto cleanup;
    }
    r = sd_bus_call_method(bus, app, obj, ifc, "GetAddress4", &error,
                            &reply, "s", nwinterface);
    if(r < 0)
    {
        fprintf(stderr, "Failed to call Get Method: %s\n", strerror(-r));
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        goto cleanup;
    }

    r = sd_bus_message_read(reply, "iyss",
                            &family, &prefixlen, &ipaddr, &gateway);
    if(r < 0)
    {
        fprintf(stderr, "Failed to get a response: %s\n", strerror(-rc));
        rc = IPMI_CC_RESPONSE_ERROR;
        goto cleanup;
    }

    printf("N/W data from HW %s:%d:%s:%s\n",
            family==AF_INET?"IPv4":"IPv6", prefixlen, ipaddr,gateway);
    printf("N/W data from Cache: %s:%s:%s\n",
            channel_config.new_ipaddr.c_str(),
            channel_config.new_netmask.c_str(),
            channel_config.new_gateway.c_str());

    if(lan_param == LAN_PARM_IP)
    {
        if(lan_set_in_progress == SET_COMPLETE)
        {
            std::string ipaddrstr(ipaddr);
            inet_pton(AF_INET, ipaddrstr.c_str(),(void *)data);
        }
        else if(lan_set_in_progress == SET_IN_PROGRESS)
        {
            inet_pton(AF_INET, channel_config.new_ipaddr.c_str(), (void *)data);
        }
    }
    else if(lan_param == LAN_PARM_SUBNET)
    {
        if(lan_set_in_progress == SET_COMPLETE)
         {
            mask = htonl(mask<<(32-prefixlen));
            memcpy(data, &mask, 4);
         }
         else if(lan_set_in_progress == SET_IN_PROGRESS)
         {
             inet_pton(AF_INET, channel_config.new_netmask.c_str(), (void *)data);
         }
    }
    else if(lan_param == LAN_PARM_GATEWAY)
    {
        if(lan_set_in_progress == SET_COMPLETE)
         {
            std::string gatewaystr(gateway);
            inet_pton(AF_INET, gatewaystr.c_str(), (void *)data);
         }
         else if(lan_set_in_progress == SET_IN_PROGRESS)
         {
             inet_pton(AF_INET, channel_config.new_gateway.c_str(),(void *)data);
         }
    }
    else
    {
        rc = IPMI_CC_PARM_OUT_OF_RANGE;
    }

cleanup:
    sd_bus_error_free(&error);
    reply = sd_bus_message_unref(reply);
    free(app);

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
    sd_bus *bus = ipmid_get_sd_bus_connection();
    sd_bus_message *reply = nullptr;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int r = 0;
    char *app = nullptr;

    char tmp_ipaddr[INET_ADDRSTRLEN];
    char tmp_netmask[INET_ADDRSTRLEN];
    char tmp_gateway[INET_ADDRSTRLEN];

    printf("IPMI SET_LAN\n");

    set_lan_t *reqptr = (set_lan_t*) request;

    if (reqptr->parameter == LAN_PARM_IP) {
        snprintf(tmp_ipaddr, INET_ADDRSTRLEN, "%d.%d.%d.%d",
            reqptr->data[0], reqptr->data[1], reqptr->data[2], reqptr->data[3]);
        channel_config.new_ipaddr.assign(tmp_ipaddr);
    } else if (reqptr->parameter == LAN_PARM_MAC) {
        char mac[SIZE_MAC];

        snprintf(mac, SIZE_MAC, "%02x:%02x:%02x:%02x:%02x:%02x",
                reqptr->data[0],
                reqptr->data[1],
                reqptr->data[2],
                reqptr->data[3],
                reqptr->data[4],
                reqptr->data[5]);

        r = mapper_get_service(bus, obj, &app);
        if (r < 0) {
            fprintf(stderr, "Failed to get %s bus name: %s\n",
                    obj, strerror(-r));
            goto finish;
        }
        r = sd_bus_call_method(bus, app, obj, ifc, "SetHwAddress", &error,
                                &reply, "ss", nwinterface, mac);
        if (r < 0) {
            fprintf(stderr, "Failed to call the method: %s\n", strerror(-r));
            rc = IPMI_CC_UNSPECIFIED_ERROR;
        }
    } else if (reqptr->parameter == LAN_PARM_SUBNET)
    {
        snprintf(tmp_netmask, INET_ADDRSTRLEN, "%d.%d.%d.%d",
            reqptr->data[0], reqptr->data[1], reqptr->data[2], reqptr->data[3]);
        channel_config.new_netmask.assign(tmp_netmask);
    } else if (reqptr->parameter == LAN_PARM_GATEWAY)
    {
        snprintf(tmp_gateway, INET_ADDRSTRLEN, "%d.%d.%d.%d",
            reqptr->data[0], reqptr->data[1], reqptr->data[2], reqptr->data[3]);
        channel_config.new_gateway.assign(tmp_gateway);
    } else if (reqptr->parameter == LAN_PARM_INPROGRESS)
    {
        if(reqptr->data[0] == SET_COMPLETE) {
            lan_set_in_progress = SET_COMPLETE;

            printf("N/W data from Cache: %s:%s:%s\n",
                    channel_config.new_ipaddr.c_str(),
                    channel_config.new_netmask.c_str(),
                    channel_config.new_gateway.c_str());
            printf("Use Set Channel Access command to apply them\n");

        } else if(reqptr->data[0] == SET_IN_PROGRESS) // Set In Progress
        {
            lan_set_in_progress = SET_IN_PROGRESS;
        }
    } else
    {
        fprintf(stderr, "Unsupported parameter 0x%x\n", reqptr->parameter);
        rc = IPMI_CC_PARM_NOT_SUPPORTED;
    }

finish:
    sd_bus_error_free(&error);
    reply = sd_bus_message_unref(reply);
    free(app);

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
    sd_bus *bus = ipmid_get_sd_bus_connection();
    sd_bus_message *reply = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int r = 0;
    const uint8_t current_revision = 0x11; // Current rev per IPMI Spec 2.0
    int i = 0;
    char *app = NULL;

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
    else if ((reqptr->parameter == LAN_PARM_IP) || (reqptr->parameter == LAN_PARM_SUBNET) || (reqptr->parameter == LAN_PARM_GATEWAY))
    {
        uint8_t buf[5];

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
    else if (reqptr->parameter == LAN_PARM_MAC)
    {
        //string to parse: link/ether xx:xx:xx:xx:xx:xx
        uint8_t buf[7];
        char *eaddr1 = NULL;

        r = mapper_get_service(bus, obj, &app);
        if (r < 0) {
            fprintf(stderr, "Failed to get %s bus name: %s\n",
                    obj, strerror(-r));
            goto cleanup;
        }
        r = sd_bus_call_method(bus, app, obj, ifc, "GetHwAddress", &error,
                                &reply, "s", nwinterface);
        if(r < 0)
        {
            fprintf(stderr, "Failed to call Get Method: %s\n", strerror(-r));
            rc = IPMI_CC_UNSPECIFIED_ERROR;
            goto cleanup;
        }

        r = sd_bus_message_read(reply, "s", &eaddr1);
        if (r < 0)
        {
            fprintf(stderr, "Failed to get a response: %s", strerror(-r));
            rc = IPMI_CC_UNSPECIFIED_ERROR;
            goto cleanup;
        }
        if (eaddr1 == NULL)
        {
            fprintf(stderr, "Failed to get a valid response: %s", strerror(-r));
            rc = IPMI_CC_UNSPECIFIED_ERROR;
            goto cleanup;
        }

        memcpy((void*)&buf[0], &current_revision, 1);

        char *tokptr = NULL;
        char* digit = strtok_r(eaddr1, ":", &tokptr);
        if (digit == NULL)
        {
            fprintf(stderr, "Unexpected MAC format: %s", eaddr1);
            rc = IPMI_CC_RESPONSE_ERROR;
            goto cleanup;
        }

        i=0;
        while (digit != NULL)
        {
            int resp_byte = strtoul(digit, NULL, 16);
            memcpy((void*)&buf[i+1], &resp_byte, 1);
            i++;
            digit = strtok_r(NULL, ":", &tokptr);
        }

        *data_len = sizeof(buf);
        memcpy(response, &buf, *data_len);
    }
    else
    {
        fprintf(stderr, "Unsupported parameter 0x%x\n", reqptr->parameter);
        rc = IPMI_CC_PARM_NOT_SUPPORTED;
    }

cleanup:
    sd_bus_error_free(&error);
    reply = sd_bus_message_unref(reply);
    free(app);

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
