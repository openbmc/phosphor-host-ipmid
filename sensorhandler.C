#include "sensorhandler.h"
#include "ipmid-api.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>


void register_netfn_sen_functions()   __attribute__((constructor));


struct sensor_data_t {
    uint8_t sennum;
}  __attribute__ ((packed)) ;

unsigned char g_sensortype [][2] = {
    {0xc7, 58},
{0x01, 113},
{0xc7, 56},
{0x01, 114},
{0xc6, 54},
{0x07, 40},
{0xC1, 121},
{0xC2, 137},
{0x07, 36},
{0x07, 43},
{0xC1, 122},
{0xC1, 119},
{0x01, 12},
{0x01, 111},
{0x01, 116},
{0xC1, 127},
{0xC2, 134},
{0xC2, 130},
{0xc, 33},
{0xC1, 125},
{0x01, 115},
{0x22, 4},
{0xC2, 138},
{0x01, 108},
{0x01, 102},
{0xc, 46},
{0x7, 11},
{0xC1, 120},
{0x07, 39},
{0x07, 42},
{0x5, 21},
{0xC2, 131},
{0xc1, 48},
{0x12, 53},
{0xC1, 124},
{0x01, 117},
{0xC1, 126},
{0xf, 5},
{0x23, 0},
{0xC2, 139},
{0x07, 34},
{0x09, 146},
{0x02, 178},
{0xC2, 140},
{0xC1, 118},
{0xC2, 133},
{0x07, 38},
{0xC2, 143},
{0x01, 101},
{0xc3, 9},
{0x7, 10},
{0xc2, 51},
{0x01, 109},
{0xc, 32},
{0x7, 8},
{0xC1, 129},
{0x01, 112},
{0x01, 107},
{0x07, 37},
{0x07, 44},
{0x1f, 50},
{0xC2, 144},
{0xc7, 52},
{0xC2, 141},
{0x01, 106},
{0x01, 110},
{0x01, 103},
{0x9, 28},
{0x07, 35},
{0xc7, 55},
{0x03, 179},
{0x07, 41},
{0xc, 30},
{0x01, 100},
{0xC1, 128},
{0xC2, 135},
{0x01, 105},
{0x7, 47},
{0xC2, 145},
{0xc7, 57},
{0x01, 104},
{0x07, 45},
{0xC2, 132},
{0xc4, 49},
{0xC1, 123},
{0xC2, 142},
{0x01, 13},
{0xC2, 136},
{0xc, 31},
{0xff,0xff}
};


unsigned char findSensor(char sensor_number) {

    int i=0;

    // TODO : This function should actually call
    // a dbus object and have it return the data
    // it is not ready yet so use a Palmetto 
    // based lookup table for now.  The g_sensortype
    // can be removed once the dbus method exists
    while (g_sensortype[i][0] != 0xff) {
        if (g_sensortype[i][1] == sensor_number) {
            break;
        } else {
            i++;
        }

    }

    return g_sensortype[i][0];

}

ipmi_ret_t ipmi_sen_get_sensor_type(ipmi_netfn_t netfn, ipmi_cmd_t cmd, 
                             ipmi_request_t request, ipmi_response_t response, 
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    sensor_data_t *reqptr = (sensor_data_t*)request;
    ipmi_ret_t rc = IPMI_CC_OK;

    printf("IPMI GET_SENSOR_TYPE [0x%02X]\n",reqptr->sennum);

    // TODO Not sure what the System-event-sensor is suppose to return
    // need to ask Hostboot team
    unsigned char buf[] = {0x00,0x6F};

    buf[0] = findSensor(reqptr->sennum);

    *data_len = sizeof(buf);
    memcpy(response, &buf, *data_len);



    return rc;
}



// TODO: Saves the sensor information to a file in /tmp.  This
// will need to change to calling the correct method 
// once it exists in the stack.  
ipmi_ret_t ipmi_sen_set_sensor(ipmi_netfn_t netfn, ipmi_cmd_t cmd, 
                             ipmi_request_t request, ipmi_response_t response, 
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    FILE *fp;
    char string[16];
    sensor_data_t *reqptr = (sensor_data_t*)request;
    ipmi_ret_t rc = IPMI_CC_OK;
    unsigned short rlen;

    rlen = (unsigned short) *data_len - 1;

    sprintf(string, "%s%02x", "/tmp/sen", reqptr->sennum);

    printf("IPMI SET_SENSOR [%s]\n",string);

    if ((fp = fopen(string, "wb")) != NULL) {
        fwrite(reqptr+1,rlen,1,fp);
        fclose(fp);
    } else {
        fprintf(stderr, "Error trying to write to sensor file %s\n",string);
        ipmi_ret_t rc = IPMI_CC_INVALID;        
    }

    *data_len=0;


    return rc;
}

ipmi_ret_t ipmi_sen_wildcard(ipmi_netfn_t netfn, ipmi_cmd_t cmd, 
                             ipmi_request_t request, ipmi_response_t response, 
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;

    printf("IPMI S/E Wildcard Netfn:[0x%X], Cmd:[0x%X]\n",netfn,cmd);
    *data_len = 0;

    return rc;
}


void register_netfn_sen_functions()
{
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_SENSOR, IPMI_CMD_WILDCARD);
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_WILDCARD, NULL, ipmi_sen_wildcard);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_SENSOR, IPMI_CMD_GET_SENSOR_TYPE);
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_GET_SENSOR_TYPE, NULL, ipmi_sen_get_sensor_type);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_SENSOR, IPMI_CMD_SET_SENSOR);
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_SET_SENSOR, NULL, ipmi_sen_set_sensor);
    return;
}
