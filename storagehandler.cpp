#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <systemd/sd-bus.h>

#include "storagehandler.h"
#include "storageaddsel.h"
#include "ipmid-api.h"

void register_netfn_storage_functions() __attribute__((constructor));


unsigned int   g_sel_time    = 0xFFFFFFFF;
extern unsigned short g_sel_reserve;

ipmi_ret_t ipmi_storage_wildcard(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    printf("Handling STORAGE WILDCARD Netfn:[0x%X], Cmd:[0x%X]\n",netfn, cmd);
    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;
    return rc;
}

ipmi_ret_t ipmi_storage_get_sel_time(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    sd_bus *bus = NULL;
    int64_t host_time = 0;
    uint32_t resp = 0;
    int rct = 0;
    ipmi_ret_t rc = IPMI_CC_OK;

    sd_bus_message *reply = NULL;
    sd_bus_error bus_error = SD_BUS_ERROR_NULL;

    printf("IPMI Handling GET-SEL-TIME\n");

    bus = ipmid_get_sd_bus_connection();

    rct = sd_bus_call_method(bus,
                    "org.openbmc.TimeManager",
                    "/org/openbmc/TimeManager",
                    "org.openbmc.TimeManager",
                    "GetHostTime",
                    &bus_error,
                    &reply,
                    NULL);
    if (rct < 0) {
        printf("Error [%s] getting time\n", strerror(-rct));
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        goto finish;
    }

    rct = sd_bus_message_read(reply, "x", &host_time);
    if (rct < 0) {
        fprintf(stderr, "Error [%s] parsing get-time response\n", strerror(-rct));
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        goto finish;
    }

    // Time is really long int but IPMI wants just uint32. This works okay until
    // the number of seconds since 1970 overflows uint32 size.. Still a whole
    // lot of time here to even think about that.
    resp = (uint32_t)host_time;
    resp = htole32(resp);
    printf("Host Time read:[%d]\n",resp);

    // From the IPMI Spec 2.0, response should be a 32-bit value
    *data_len = sizeof(resp);

    // Pack the actual response
    memcpy(response, &resp, *data_len);

finish:
    sd_bus_error_free(&bus_error);
    reply = sd_bus_message_unref(reply);
    return rc;
}

ipmi_ret_t ipmi_storage_set_sel_time(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    const char *err_str = NULL;
    int time_rc = 0;
    int64_t time_in_sec = 0;
    int rct = 0;
    sd_bus *bus = NULL;
    ipmi_ret_t rc = IPMI_CC_OK;

    sd_bus_message *reply = NULL;
    sd_bus_error bus_error = SD_BUS_ERROR_NULL;

    uint32_t* secs = (uint32_t*)request;
    *data_len = 0;

    printf("Handling Set-SEL-Time:[0x%X], Cmd:[0x%X]\n",netfn, cmd);
    printf("Data: 0x%X]\n",*secs);

    time_in_sec = le32toh(*secs);

    bus = ipmid_get_sd_bus_connection();

    rct = sd_bus_call_method(bus,
		    "org.openbmc.TimeManager",
		    "/org/openbmc/TimeManager",
		    "org.openbmc.TimeManager",
		    "SetHostTime",
		    &bus_error,
		    &reply,
		    "x",
		    (int64_t)time_in_sec);

    if (rct < 0) {
        printf("Error [%s] setting time\n", strerror(-rct));
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        goto finish;
    }

    rct = sd_bus_message_read(reply, "is", &time_rc, &err_str);
    if (rct < 0) {
        fprintf(stderr, "Error [%s] parsing set-time response\n", strerror(-rct));
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        goto finish;
    }

    if (time_rc < 0) {
        printf("Error setting time. ErrorMessage:[%s]\n",err_str);
        rc = IPMI_CC_UNSPECIFIED_ERROR;
    }

finish:
    sd_bus_error_free(&bus_error);
    reply = sd_bus_message_unref(reply);
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
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_WILDCARD);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_WILDCARD, NULL, ipmi_storage_wildcard);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_GET_SEL_TIME);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_GET_SEL_TIME, NULL, ipmi_storage_get_sel_time);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_SET_SEL_TIME);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_SET_SEL_TIME, NULL, ipmi_storage_set_sel_time);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_GET_SEL_INFO);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_GET_SEL_INFO, NULL, ipmi_storage_get_sel_info);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_RESERVE_SEL);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_RESERVE_SEL, NULL, ipmi_storage_reserve_sel);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_ADD_SEL);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_ADD_SEL, NULL, ipmi_storage_add_sel);
    return;
}

