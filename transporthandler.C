#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "ipmid-api.h"
#include "ipmid.H"
#include "transporthandler.h"

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
    char syscmd[128];

    printf("IPMI SET_LAN\n");

    set_lan_t *reqptr = (set_lan_t*) request;

    // TODO Use dbus interface once available. For now use cmd line.
    // TODO Add the rest of the parameters like setting auth type
    // TODO Add error handling

    if (reqptr->parameter == 3) // IP
    {
        sprintf(syscmd, "ifconfig eth0 %d.%d.%d.%d", reqptr->data[0], reqptr->data[1], reqptr->data[2], reqptr->data[3]);
        system(syscmd);
    }
    else if (reqptr->parameter == 6) // Subnet
    {
        sprintf(syscmd, "ifconfig eth0 netmask %d.%d.%d.%d", reqptr->data[0], reqptr->data[1], reqptr->data[2], reqptr->data[3]);
        system(syscmd);
    }
    else if (reqptr->parameter == 12) // Gateway
    {
        sprintf(syscmd, "route add default gw %d.%d.%d.%d", reqptr->data[0], reqptr->data[1], reqptr->data[2], reqptr->data[3]);
        system(syscmd);
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

    const uint8_t current_revision = 0x11; // Current rev per IPMI Spec 2.0
    char syscmd[128];
    int i = 0;

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
        //string to parse: inet xx.xx.xxx.xxx/xx

        uint8_t buf[5];
        memcpy((void*)&buf[0], &current_revision, 1);

        for (i=0; i<4; i++)
        {
            char ip[5];

            sprintf(syscmd, "ip address show dev eth0|grep inet|cut -d'/' -f1|cut -d' ' -f 6|cut -d'.' -f%d|head -n1", i+1);
            FILE *fp = popen(syscmd, "r");

            memset(ip,0,sizeof(ip));
            while (fgets(ip, sizeof(ip), fp) != 0)
            {
                int tmpip = strtoul(ip, NULL, 10);
                memcpy((void*)&buf[i+1], &tmpip, 1);
            }
            pclose(fp);
        }

        *data_len = sizeof(buf);
        memcpy(response, &buf, *data_len);
        return IPMI_CC_OK;
    }
    else if (reqptr->parameter == 5) // MAC
    {
        //string to parse: link/ether xx:xx:xx:xx:xx:xx

        uint8_t buf[7];
        memcpy((void*)&buf[0], &current_revision, 1);

        for (i=0; i<6; i++)
        {
            char mac[4];

            sprintf(syscmd, "ip address show dev eth0|grep link|cut -d' ' -f 6|cut -d':' -f%d", i+1);
            FILE *fp = popen(syscmd, "r");

            memset(mac,0,sizeof(mac));
            while (fgets(mac, sizeof(mac), fp) != 0)
            {
                int tmpmac = strtoul(mac, NULL, 16);
                memcpy((void*)&buf[i+1], &tmpmac, 1);
            }
            pclose(fp);
        }

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

