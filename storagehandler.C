#include "storagehandler.h"
#include "ipmid-api.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

void register_netfn_storage_functions() __attribute__((constructor));


unsigned int   g_sel_time    = 0xFFFFFFFF;
unsigned short g_sel_reserve = 0x1;

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


ipmi_ret_t ipmi_storage_set_sel_time(ipmi_netfn_t netfn, ipmi_cmd_t cmd, 
                              ipmi_request_t request, ipmi_response_t response, 
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    unsigned int *bufftype = (unsigned int *) request;

    printf("Handling Set-SEL-Time:[0x%X], Cmd:[0x%X]\n",netfn, cmd);
    printf("Data: 0x%X]\n",*bufftype);

    g_sel_time = *bufftype;

    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;
    return rc;
}

struct write_fru_data_t {
    uint8_t  frunum;
    uint8_t  offsetls;
    uint8_t  offsetms;
    uint8_t  data;
} __attribute__ ((packed)) ;

ipmi_ret_t ipmi_storage_write_fru_data(ipmi_netfn_t netfn, ipmi_cmd_t cmd, 
                              ipmi_request_t request, ipmi_response_t response, 
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    write_fru_data_t *reqptr = (write_fru_data_t*) request;
    FILE *fp;
    char string[16];
    short offset = 0;
    uint16_t rlen;
    ipmi_ret_t rc = IPMI_CC_OK;
    char iocmd[4];

    sprintf(string, "%s%02x", "/tmp/fru", reqptr->frunum);

    offset = ((uint16_t)reqptr->offsetms) << 8 | reqptr->offsetls;


    // Length is the number of request bytes minus the header itself.
    // The header contains an extra byte to indicate the start of
    // the data (so didn't need to worry about word/byte boundaries)
    // hence the -1...
    rlen = ((uint16_t)*data_len) - (sizeof(write_fru_data_t)-1);
    

    printf("IPMI WRITE-FRU-DATA for %s  Offset = %d Length = %d\n",
        string, offset, rlen);


    // I was thinking "ab+" but it appears it doesn't
    // do what fseek asks.  Modify to rb+ and fseek 
    // works great...
    if (offset == 0) {
        strcpy(iocmd, "wb");
    } else {
        strcpy(iocmd, "rb+");
    }

    if ((fp = fopen(string, iocmd)) != NULL) {
        fseek(fp, offset, SEEK_SET);
        fwrite(&reqptr->data,rlen,1,fp);
        fclose(fp);
    } else {
        fprintf(stderr, "Error trying to write to fru file %s\n",string);
        ipmi_ret_t rc = IPMI_CC_INVALID;        
    }
    

    // TODO : Here is where some validation code could determine if the 
    // fru data is a legitimate FRU record (not just a partial).  Once
    // the record is valid the code should call a parser routine to call
    // the various methods updating interesting properties.  Perhaps 
    // thinigs like Model#, Serial#, DIMM Size, etc
    

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

    ipmi_ret_t rc = IPMI_CC_OK;

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

    printf("IPMI Handling ADD-SEL \n");

    *data_len = sizeof(g_sel_reserve);

    // Pack the actual response
    memcpy(response, &g_sel_reserve, *data_len);

    // TODO This code should grab the completed partial esel located in 
    // the /tmp/esel0100 file and commit it to the error log handler.  


    // TODO I advanced the sel reservation number so next time HB asks
    // for a reservation they get a new number.  This tech may change 
    // based on how the HB team currently uses sel reservations but
    // for now provide the ability to get new reservations 
    g_sel_reserve++;

    return rc;
}



void register_netfn_storage_functions()
{
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_WILDCARD);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_WILDCARD, NULL, ipmi_storage_wildcard);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_SET_SEL_TIME);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_SET_SEL_TIME, NULL, ipmi_storage_set_sel_time);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_WRITE_FRU_DATA);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_WRITE_FRU_DATA, NULL, ipmi_storage_write_fru_data);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_GET_SEL_INFO);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_GET_SEL_INFO, NULL, ipmi_storage_get_sel_info);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_RESERVE_SEL);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_RESERVE_SEL, NULL, ipmi_storage_reserve_sel);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_ADD_SEL);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_ADD_SEL, NULL, ipmi_storage_add_sel);
    return;
}

