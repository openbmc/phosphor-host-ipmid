#include "sensorhandler.h"
#include "ipmid-api.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

extern int updateSensorRecordFromSSRAESC(const void *);
extern int find_interface_property_fru_type(dbus_interface_t *interface, const char *property_name, char *property_value) ;
extern int find_openbmc_path(const char *type, const uint8_t num, dbus_interface_t *interface) ;

void register_netfn_sen_functions()   __attribute__((constructor));


struct sensorTypemap_t {
    uint8_t number;
    char dbusname[32];
} ;


sensorTypemap_t g_SensorTypeMap[] = {

    {0x01, "Temp"},
    {0x0C, "DIMM"},
    {0x07, "PROC"},
    {0x0F, "BootProgress"},
    {0xC3, "OccStatus"},
    {0xC3, "BootCount"},
    {0xFF, ""}
};


struct sensor_data_t {
    uint8_t sennum;
}  __attribute__ ((packed)) ;


uint8_t dbus_to_sensor_type(char *p) {

    sensorTypemap_t *s = g_SensorTypeMap;
    char r=0;

    printf("Looking for Sensor Type %s\n", p);

    while (s->number != 0xFF) {
        if (!strcmp(s->dbusname,p)) {
            r = s->number;
            break;
        }
        s++;
    }
    return r;
}


uint8_t dbus_to_sensor_type_from_dbus(dbus_interface_t *a) {
    char fru_type_name[64];
    int r= 0;

    r = find_interface_property_fru_type(a, "fru_type", fru_type_name);
    if (r<0) {
        fprintf(stderr, "Failed to get a fru type: %s", strerror(-r));
        return -1;
    } else {
        return dbus_to_sensor_type(fru_type_name);
    }

}


uint8_t find_sensor(uint8_t sensor_number) {

    dbus_interface_t a;
    char *p;
    char r;

    r = find_openbmc_path("SENSOR", sensor_number, &a);

    if (r < 0) { return 0; }

    printf("bus: %s\n", a.bus);
    printf("path: %s\n", a.path);
    printf("interface: %s\n", a.interface);

    if (strstr(a.interface, "InventoryItem")) {
        // InventoryItems are real frus.  So need to get the
        // fru_type property
        r = dbus_to_sensor_type_from_dbus(&a);
    } else {
        // Non InventoryItems
        p = strrchr (a.path, '/');
        r = dbus_to_sensor_type(p+1);
    }

    return r;
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

    buf[0] = find_sensor(reqptr->sennum);

    *data_len = sizeof(buf);
    memcpy(response, &buf, *data_len);



    return rc;
}


ipmi_ret_t ipmi_sen_set_sensor(ipmi_netfn_t netfn, ipmi_cmd_t cmd, 
                             ipmi_request_t request, ipmi_response_t response, 
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    sensor_data_t *reqptr = (sensor_data_t*)request;
    ipmi_ret_t rc = IPMI_CC_OK;
    unsigned short rlen;

    rlen = (unsigned short) *data_len;

    printf("IPMI SET_SENSOR [0x%02x]\n",reqptr->sennum);

    updateSensorRecordFromSSRAESC(reqptr);

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
