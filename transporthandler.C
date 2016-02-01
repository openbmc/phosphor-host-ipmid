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

    printf("IPMI SET_LAN\n");

    set_lan_t *reqptr = (set_lan_t*) request;

    // TODO Use dbus interface once available. For now use cmd line.
    // TODO Add the rest of the parameters like setting auth type
    // TODO Add error handling

    if (reqptr->parameter == 3) // IP
    {
        sprintf(new_ipaddr, "%d.%d.%d.%d", reqptr->data[0], reqptr->data[1], reqptr->data[2], reqptr->data[3]);
    }
    else if (reqptr->parameter == 6) // Subnet
    {
        sprintf(new_netmask, "%d.%d.%d.%d", reqptr->data[0], reqptr->data[1], reqptr->data[2], reqptr->data[3]);
    }
    else if (reqptr->parameter == 12) // Gateway
    {
        sprintf(new_gateway, "%d.%d.%d.%d", reqptr->data[0], reqptr->data[1], reqptr->data[2], reqptr->data[3]);
    }
    else if (reqptr->parameter == 0) // Apply config
    {
        int rc = 0;
        sd_bus_message *req = NULL;
        sd_bus_message *res = NULL;
        sd_bus *bus         = NULL;
        sd_bus_error err    = SD_BUS_ERROR_NULL;
        
        if (!strcmp(new_ipaddr, "") || !strcmp (new_netmask, "") || !strcmp (new_gateway, ""))
        {
            fprintf(stderr,"ERROR: Incomplete LAN Parameters\n");
            return -1;
        }
            
        rc = sd_bus_open_system(&bus);
        if(rc < 0)
        {
            fprintf(stderr,"ERROR: Getting a SYSTEM bus hook\n");
            return -1;
        }

        if (strcmp(cur_ipaddr, ""))
        {
            sd_bus_error_free(&err);
            sd_bus_message_unref(req);
            sd_bus_message_unref(res);

            rc = sd_bus_call_method(bus,            // On the System Bus
                                    app,            // Service to contact
                                    obj,            // Object path 
                                    ifc,            // Interface name
                                    "DelAddress4",  // Method to be called
                                    &err,           // object to return error
                                    &res,           // Response message on success
                                    "ssss",         // input message (dev,ip,nm,gw)
                                    "eth0",
                                    cur_ipaddr,
                                    cur_netmask,
                                    cur_gateway);
        }

        if(rc < 0)
        {
            fprintf(stderr, "Failed to remove existing IP %s: %s\n", cur_ipaddr, err.message);
            return -1;
        }

        sd_bus_error_free(&err);
        sd_bus_message_unref(req);
        sd_bus_message_unref(res);

        rc = sd_bus_call_method(bus,            // On the System Bus
                                app,            // Service to contact
                                obj,            // Object path 
                                ifc,            // Interface name
                                "AddAddress4",  // Method to be called
                                &err,           // object to return error
                                &res,           // Response message on success
                                "ssss",         // input message (dev,ip,nm,gw)
                                "eth0",
                                new_ipaddr,
                                new_netmask,
                                new_gateway);
        if(rc < 0)
        {
            fprintf(stderr, "Failed to set IP %s: %s\n", new_ipaddr, err.message);
            return -1;
        }

        strcpy (cur_ipaddr, new_ipaddr);
        strcpy (cur_netmask, new_netmask);
        strcpy (cur_gateway, new_gateway);
    }
    else
    {
        fprintf(stderr, "Unsupported parameter 0x%x\n", reqptr->parameter);
        return IPMI_CC_PARM_NOT_SUPPORTED;
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
    sd_bus_error err    = SD_BUS_ERROR_NULL; /* fixme */
    const uint8_t current_revision = 0x11; // Current rev per IPMI Spec 2.0

    int                 family;
    unsigned char       prefixlen;
    unsigned char       scope;
    unsigned int        flags;
    char                saddr [128];
    char                gateway [128];
    uint8_t             buf[11];

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

    if (reqptr->parameter == 0) // In progress
    {
        uint8_t buf[] = {current_revision,0};
        *data_len = sizeof(buf);
        memcpy(response, &buf, *data_len);
        return IPMI_CC_OK;
    }
    else if (reqptr->parameter == 1) // Authentication support
    {
        uint8_t buf[] = {current_revision,0x04};
        *data_len = sizeof(buf);
        memcpy(response, &buf, *data_len);
        return IPMI_CC_OK;
    }
    else if (reqptr->parameter == 2) // Authentication enables
    {
        uint8_t buf[] = {current_revision,0x04,0x04,0x04,0x04,0x04};
        *data_len = sizeof(buf);
        memcpy(response, &buf, *data_len);
        return IPMI_CC_OK;
    }
    else if (reqptr->parameter == 3) // IP
    {
        const char*         device             = "eth0";

        sd_bus_message *res = NULL;
        sd_bus *bus         = NULL;
        sd_bus_error err    = SD_BUS_ERROR_NULL;

        rc = sd_bus_open_system(&bus);
        if(rc < 0)
        {
            fprintf(stderr,"ERROR: Getting a SYSTEM bus hook\n");
            return -1;
        }

        rc = sd_bus_call_method(bus,            // On the System Bus
                                app,            // Service to contact
                                obj,            // Object path 
                                ifc,            // Interface name
                                "GetAddress4",  // Method to be called
                                &err,           // object to return error
                                &res,           // Response message on success
                                "s",         // input message (dev,ip,nm,gw)
                                "eth0");
        if(rc < 0)
        {
            fprintf(stderr, "Failed to Get IP on interface : %s\n", device);
            return -1;
        }

        /* rc = sd_bus_message_read(res, "a(iyyus)s", ...); */
        rc = sd_bus_message_enter_container (res, 'a', "(iyyus)");
        if(rc < 0)
        {
            fprintf(stderr, "Failed to parse response message:[%s]\n", strerror(-rc));
            return -1;
        }

        while ((rc = sd_bus_message_read(res, "(iyyus)", &family, &prefixlen, &scope, &flags, &saddr)) > 0) {
                printf("%s:%d:%d:%d:%s\n", family==AF_INET?"IPv4":"IPv6", prefixlen, scope, flags, saddr);
        }

        rc = sd_bus_message_read (res, "s", &gateway);
        if(rc < 0)
        {
            fprintf(stderr, "Failed to parse gateway from response message:[%s]\n", strerror(-rc));
            return -1;
        }

        memcpy((void*)&buf[0], &current_revision, 1);
        sscanf (saddr, "%c.%c.%c.%c", &buf[1], &buf[2], &buf[3], &buf[4]);
        buf[5] = family;
        buf[6] = prefixlen;
        sscanf (gateway, "%c.%c.%c.%c", &buf[7], &buf[8], &buf[9], &buf[10]);

        *data_len = sizeof(buf);
        memcpy(response, &buf, *data_len);

        return IPMI_CC_OK;
    }
    else if (reqptr->parameter == 5) // MAC
    {
        //string to parse: link/ether xx:xx:xx:xx:xx:xx

        const char*         device             = "eth0";
        char                eaddr [12];
        uint8_t             buf[7];

        sd_bus_message *res = NULL;
        sd_bus *bus         = NULL;
        sd_bus_error err    = SD_BUS_ERROR_NULL;

        rc = sd_bus_open_system(&bus);
        if(rc < 0)
        {
            fprintf(stderr,"ERROR: Getting a SYSTEM bus hook\n");
            return -1;
        }

        rc = sd_bus_call_method(bus,            // On the System Bus
                                app,            // Service to contact
                                obj,            // Object path 
                                ifc,            // Interface name
                                "GetHwAddress",  // Method to be called
                                &err,           // object to return error
                                &res,           // Response message on success
                                "s",         // input message (dev,ip,nm,gw)
                                device);
        if(rc < 0)
        {
            fprintf(stderr, "Failed to Get HW address of device : %s\n", device);
            return -1;
        }

        rc = sd_bus_message_read (res, "s", &eaddr);
        if(rc < 0)
        {
            fprintf(stderr, "Failed to parse gateway from response message:[%s]\n", strerror(-rc));
            return -1;
        }

        memcpy((void*)&buf[0], &current_revision, 1);
        sscanf (eaddr, "%x:%x:%x:%x:%x:%x", &buf[1], &buf[2], &buf[3], &buf[4], &buf[5], &buf[6]);

        *data_len = sizeof(buf);
        memcpy(response, &buf, *data_len);

        return IPMI_CC_OK;
    }
    else
    {
        fprintf(stderr, "Unsupported parameter 0x%x\n", reqptr->parameter);
        return IPMI_CC_PARM_NOT_SUPPORTED;
    }

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
