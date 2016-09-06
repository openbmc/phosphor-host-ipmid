#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include "storagehandler.h"
#include "storageaddsel.h"
#include "host-ipmid/ipmid-api.h"

void register_netfn_storage_functions() __attribute__((constructor));


unsigned int   g_sel_time    = 0xFFFFFFFF;
extern unsigned short g_sel_reserve;

ipmi_ret_t ipmi_storage_wildcard(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    printf("Handling STORAGE WILDCARD Netfn:[0x%X], Cmd:[0x%X]\n",netfn, cmd);
    // Status code.
    ipmi_ret_t rc = IPMI_CC_INVALID;
    *data_len = 0;
    return rc;
}

ipmi_ret_t ipmi_storage_get_sel_time(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    time_t currtime;
    ipmi_ret_t rc = IPMI_CC_OK;

    // Get current time in seconds since jan 1 1970
    time(&currtime);
    uint32_t resp = (uint32_t)currtime;
    resp = htole32(resp);

    printf("IPMI Handling GET-SEL-TIME\n");

    // From the IPMI Spec 2.0, response should be a 32-bit value
    *data_len = sizeof(resp);

    // Pack the actual response
    memcpy(response, &resp, *data_len);

    return rc;
}

ipmi_ret_t ipmi_storage_set_sel_time(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    uint32_t* secs = (uint32_t*)request;

    printf("Handling Set-SEL-Time:[0x%X], Cmd:[0x%X]\n",netfn, cmd);
    printf("Data: 0x%X]\n",*secs);

    struct timeval sel_time;
    sel_time.tv_sec = le32toh(*secs);
    sel_time.tv_usec = 0;
    ipmi_ret_t rc = IPMI_CC_OK;
    int rct = settimeofday(&sel_time, NULL);

    if(rct == 0)
    {
	system("hwclock -w");
    }
    else
    {
        printf("settimeofday() failed\n");
        rc = IPMI_CC_UNSPECIFIED_ERROR;
    }
    *data_len = 0;
    return rc;
}

ipmi_ret_t ipmi_storage_get_sel_info(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{

    ipmi_ret_t rc = IPMI_CC_OK;
    unsigned char buf[] = {0x51,0,0,0xff, 0xff,0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,0x06};

    printf("IPMI Handling GET-SEL-INFO\n");

    *data_len = sizeof(buf);

    // TODO There is plently of work here.  The SEL DB needs to hold a bunch
    // of things in a header.  Items like Time Stamp, number of entries, etc
    // This is one place where the dbus object with the SEL information could
    // mimic what IPMI needs.

    // Pack the actual response
    memcpy(response, &buf, *data_len);

    return rc;
}

ipmi_ret_t ipmi_storage_reserve_sel(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    unsigned short res_id;

    ipmi_ret_t rc = IPMI_CC_OK;

    // IPMI spec, Reservation ID, the value simply increases against each execution of reserve_sel command.
    if( ++g_sel_reserve == 0)
        g_sel_reserve = 1;

    printf("IPMI Handling RESERVE-SEL 0x%04x\n", g_sel_reserve);

    *data_len = sizeof(g_sel_reserve);

    // Pack the actual response
    memcpy(response, &g_sel_reserve, *data_len);

    return rc;
}

ipmi_ret_t ipmi_storage_add_sel(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{

    ipmi_ret_t rc = IPMI_CC_OK;
    ipmi_add_sel_request_t *p = (ipmi_add_sel_request_t*) request;
    uint16_t recordid;

    recordid = ((uint16_t)p->eventdata[1] << 8) | p->eventdata[2];

    printf("IPMI Handling ADD-SEL for record 0x%04x\n", recordid);

    *data_len = sizeof(g_sel_reserve);

    // Pack the actual response
    memcpy(response, &p->eventdata[1], 2);

    send_esel(recordid);

    return rc;
}



void register_netfn_storage_functions()
{
    ipmi_cmd_data_t command_data;
    command_data.canExecuteSessionless = false;
    command_data.privilegeMask = IPMI_SESSION_PRIVILEGE_ANY;
    command_data.supportedChannels = IPMI_CHANNEL_ANY;
    command_data.commandSupportMask = IPMI_COMMAND_SUPPORT_NO_DISABLE;

    // <Wildcard Command>
    command_data.privilegeMask = IPMI_SESSION_PRIVILEGE_USER;
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_WILDCARD);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_WILDCARD, NULL, ipmi_storage_wildcard,
                           command_data);

    // <Get SEL Time>
    command_data.privilegeMask = IPMI_SESSION_PRIVILEGE_USER;
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_GET_SEL_TIME);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_GET_SEL_TIME, NULL, ipmi_storage_get_sel_time,
                           command_data);

    // <Set SEL Time>
    command_data.privilegeMask = IPMI_SESSION_PRIVILEGE_OPERATOR;
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_SET_SEL_TIME);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_SET_SEL_TIME, NULL, ipmi_storage_set_sel_time,
                           command_data);

    // <Get SEL Info>
    command_data.privilegeMask = IPMI_SESSION_PRIVILEGE_USER;
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_GET_SEL_INFO);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_GET_SEL_INFO, NULL, ipmi_storage_get_sel_info,
                           command_data);

    // <Reserve SEL>
    command_data.privilegeMask = IPMI_SESSION_PRIVILEGE_USER;
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_RESERVE_SEL);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_RESERVE_SEL, NULL, ipmi_storage_reserve_sel,
                           command_data);

    // <Add SEL Entry>
    command_data.privilegeMask = IPMI_SESSION_PRIVILEGE_OPERATOR;
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_ADD_SEL);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_ADD_SEL, NULL, ipmi_storage_add_sel,
                           command_data);
    return;
}

