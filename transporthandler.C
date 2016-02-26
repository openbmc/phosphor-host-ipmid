#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "ipmid-api.h"
#include "ipmid.H"
#include "transporthandler.h"

#define SYSTEMD_NETWORKD_DBUS 1

#ifdef SYSTEMD_NETWORKD_DBUS
#include <systemd/sd-bus.h>
#endif

// OpenBMC System Manager dbus framework
const char  *app   =  "org.openbmc.NetworkManager";
const char  *obj   =  "/org/openbmc/NetworkManager/Interface";
const char  *ifc   =  "org.openbmc.NetworkManager";

const int SIZE_MAC = 18; //xx:xx:xx:xx:xx:xx
const int SIZE_LAN_PARM = 16; //xxx.xxx.xxx.xxx

char cur_ipaddr  [16] = "";
char cur_netmask [16] = "";
char cur_gateway [16] = "";

char new_ipaddr  [16] = "";
char new_netmask [16] = "";
char new_gateway [16] = "";

void register_netfn_transport_functions() __attribute__((constructor));

ipmi_ret_t ipmi_transport_wildcard(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    printf("Handling TRANSPORT WILDCARD Netfn:[0x%X], Cmd:[0x%X]\n",netfn, cmd);
    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;
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
    sd_bus_message *reply = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int r = 0;

    printf("IPMI SET_LAN\n");

    set_lan_t *reqptr = (set_lan_t*) request;

    // TODO Use dbus interface once available. For now use cmd line.
    // TODO Add the rest of the parameters like setting auth type
    // TODO Add error handling

    if (reqptr->parameter == LAN_PARM_IP)
    {
        snprintf(new_ipaddr, SIZE_LAN_PARM, "%d.%d.%d.%d",
            reqptr->data[0], reqptr->data[1], reqptr->data[2], reqptr->data[3]);
    }
    else if (reqptr->parameter == LAN_PARM_MAC)
    {
        char                mac[SIZE_MAC];

        snprintf(mac, SIZE_MAC, "%02x:%02x:%02x:%02x:%02x:%02x",
                reqptr->data[0],
                reqptr->data[1],
                reqptr->data[2],
                reqptr->data[3],
                reqptr->data[4],
                reqptr->data[5]);

        r = sd_bus_call_method(bus,app,obj,ifc,"SetHwAddress",
                               &error, &reply, "s", mac);
        if (r < 0) {
            fprintf(stderr, "Failed to call method: %s\n", strerror(-r));
        }
    }
    else if (reqptr->parameter == LAN_PARM_SUBNET)
    {
        snprintf(new_netmask, SIZE_LAN_PARM, "%d.%d.%d.%d",
            reqptr->data[0], reqptr->data[1], reqptr->data[2], reqptr->data[3]);
    }
    else if (reqptr->parameter == LAN_PARM_GATEWAY)
    {
        snprintf(new_gateway, SIZE_LAN_PARM, "%d.%d.%d.%d",
            reqptr->data[0], reqptr->data[1], reqptr->data[2], reqptr->data[3]);
    }
    else if (reqptr->parameter == LAN_PARM_INPROGRESS) // Apply config
    {
        if (!strcmp(new_ipaddr, "") || !strcmp (new_netmask, "") || !strcmp (new_gateway, ""))
        {
            fprintf(stderr,"ERROR: Incomplete LAN Parameters\n");
            return -1;
        }

        if (strcmp(cur_ipaddr, ""))
        {
            r = sd_bus_call_method(bus,           // On the System Bus
                                   app,            // Service to contact
                                   obj,            // Object path
                                   ifc,            // Interface name
                                   "DelAddress4",  // Method to be called
                                   &error,         // object to return error
                                   &reply,         // Response message on success
                                   "ssss",         // input message (dev,ip,nm,gw)
                                   "eth0",
                                   cur_ipaddr,
                                   cur_netmask,
                                   cur_gateway);
        }

        if(r < 0)
        {
            fprintf(stderr, "Failed to remove existing IP %s: %s\n", cur_ipaddr, error.message);
            goto finish;
        }

        sd_bus_error_free(&error);
        reply = sd_bus_message_unref(reply);

        r = sd_bus_call_method(bus,            // On the System Bus
                               app,            // Service to contact
                               obj,            // Object path
                               ifc,            // Interface name
                               "AddAddress4",  // Method to be called
                               &error,         // object to return error
                               &reply,         // Response message on success
                               "ssss",         // input message (dev,ip,nm,gw)
                               "eth0",
                               new_ipaddr,
                               new_netmask,
                               new_gateway);
        if(r < 0)
        {
            fprintf(stderr, "Failed to set IP %s: %s\n", new_ipaddr, error.message);
        }
        else
        {
            strcpy (cur_ipaddr, new_ipaddr);
            strcpy (cur_netmask, new_netmask);
            strcpy (cur_gateway, new_gateway);
        }
    }
    else
    {
        fprintf(stderr, "Unsupported parameter 0x%x\n", reqptr->parameter);
        rc = IPMI_CC_PARM_NOT_SUPPORTED;
    }

finish:
    // Clenaup the resources allocated reply and error
    sd_bus_error_free(&error);
    reply = sd_bus_message_unref(reply);

    return (r < 0) ? -1 : rc;
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

    int                 family;
    unsigned char       prefixlen;
    unsigned char       scope;
    unsigned int        flags;
    char               *saddr = NULL;
    int                 i = 0;

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
        uint8_t buf[] = {current_revision,0};
        *data_len = sizeof(buf);
        memcpy(response, &buf, *data_len);
        return IPMI_CC_OK;
    }
    else if (reqptr->parameter == LAN_PARM_AUTHSUPPORT)
    {
        uint8_t buf[] = {current_revision,0x04};
        *data_len = sizeof(buf);
        memcpy(response, &buf, *data_len);
        return IPMI_CC_OK;
    }
    else if (reqptr->parameter == LAN_PARM_AUTHENABLES)
    {
        uint8_t buf[] = {current_revision,0x04,0x04,0x04,0x04,0x04};
        *data_len = sizeof(buf);
        memcpy(response, &buf, *data_len);
        return IPMI_CC_OK;
    }
    else if (reqptr->parameter == LAN_PARM_IP)
    {
        const char*         device             = "eth0";
        uint8_t buf[5]; // Size of expected IPMI response msg

        r = sd_bus_call_method(bus,app,obj,ifc,"GetAddress4",
                               &error, &reply, "s", device);
        if (r < 0)
        {
            fprintf(stderr, "Failed to call method: %s\n", strerror(-r));
            rc = -1;
            goto finish;
        }
        r = sd_bus_message_enter_container (reply, 'a', "(iyyus)");
        if(r < 0)
        {
            fprintf(stderr, "Failed to parse response message:[%s]\n", strerror(-rc));
            rc = -1;
            goto finish;
        }
        r = sd_bus_message_read(reply, "(iyyus)", &family, &prefixlen, &scope, &flags, &saddr);
        if (r < 0)
        {
            fprintf(stderr, "Failed to receive response: %s\n", strerror(-r));
            rc = -1;
            goto finish;
        }

        printf("%s:%d:%d:%d:%s\n", family==AF_INET?"IPv4":"IPv6", prefixlen, scope, flags, saddr);

        memcpy((void*)&buf[0], &current_revision, 1);

        // Parse IP address
        char *tokptr = NULL;
        char* digit = strtok_r(saddr, ".", &tokptr);
        if (digit == NULL)
        {
            fprintf(stderr, "Unexpected IP format: %s", saddr);
            rc = IPMI_CC_RESPONSE_ERROR;
            goto finish;
        }
        i = 0;
        while (digit != NULL)
        {
            int resp_byte = strtoul(digit, NULL, 10);
            memcpy((void*)&buf[i+1], &resp_byte, 1);
            i++;
            digit = strtok_r(NULL, ".", &tokptr);
        }

        *data_len = sizeof(buf);
        memcpy(response, &buf, *data_len);

        rc = IPMI_CC_OK;
    }
    else if (reqptr->parameter == LAN_PARM_MAC)
    {
        //string to parse: link/ether xx:xx:xx:xx:xx:xx

        const char*         device             = "eth0";
        uint8_t             buf[7];
        char *eaddr1 = NULL;

        r = sd_bus_call_method(bus,app,obj,ifc,"GetHwAddress",
                               &error, &reply, "s", device);
        if (r < 0)
        {
            fprintf(stderr, "Failed to call GetHwAddress: %s\n", strerror(-r));
            rc = -1;
            goto finish;
        }
        r = sd_bus_message_read(reply, "s", &eaddr1);
        if (r < 0)
        {
            fprintf(stderr, "Failed to get a response: %s", strerror(-r));
            rc = IPMI_CC_RESPONSE_ERROR;
            goto finish;
        }
        if (eaddr1 == NULL)
        {
            fprintf(stderr, "Failed to get a valid response: %s", strerror(-r));
            rc = IPMI_CC_RESPONSE_ERROR;
            goto finish;
        }

        memcpy((void*)&buf[0], &current_revision, 1);

        char *tokptr = NULL;
        char* digit = strtok_r(eaddr1, ":", &tokptr);
        if (digit == NULL)
        {
            fprintf(stderr, "Unexpected MAC format: %s", eaddr1);
            rc = IPMI_CC_RESPONSE_ERROR;
            goto finish;
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

        rc = IPMI_CC_OK;
    }
    else
    {
        fprintf(stderr, "Unsupported parameter 0x%x\n", reqptr->parameter);
        rc = IPMI_CC_PARM_NOT_SUPPORTED;
    }

finish:
    sd_bus_error_free(&error);
    reply = sd_bus_message_unref(reply);

    return rc;
}

void register_netfn_transport_functions()
{
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_TRANSPORT, IPMI_CMD_WILDCARD);
    ipmi_register_callback(NETFUN_TRANSPORT, IPMI_CMD_WILDCARD, NULL, ipmi_transport_wildcard);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_TRANSPORT, IPMI_CMD_SET_LAN);
    ipmi_register_callback(NETFUN_TRANSPORT, IPMI_CMD_SET_LAN, NULL, ipmi_transport_set_lan);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_TRANSPORT, IPMI_CMD_GET_LAN);
    ipmi_register_callback(NETFUN_TRANSPORT, IPMI_CMD_GET_LAN, NULL, ipmi_transport_get_lan);

    return;
}
