#include "sensorhandler.h"
#include "ipmid-api.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <systemd/sd-bus.h>

extern int updateSensorRecordFromSSRAESC(const void *);
extern int find_interface_property_fru_type(dbus_interface_t *interface, const char *property_name, char *property_value) ;
extern int find_openbmc_path(const char *type, const uint8_t num, dbus_interface_t *interface) ;

void register_netfn_sen_functions()   __attribute__((constructor));

struct sensorTypemap_t {
    uint8_t number;
    uint8_t typecode;
    char dbusname[32];
} ;


sensorTypemap_t g_SensorTypeMap[] = {

    {0x01, 0x6F, "Temp"},
    {0x0C, 0x6F, "DIMM"},
    {0x0C, 0x6F, "MEMORY_BUFFER"},
    {0x07, 0x6F, "PROC"},
    {0x07, 0x6F, "CORE"},
    {0x07, 0x6F, "CPU"},
    {0x0F, 0x6F, "BootProgress"},
    {0xe9, 0x09, "OccStatus"},  // E9 is an internal mapping to handle sensor type code os 0x09
    {0xC3, 0x6F, "BootCount"},
    {0x1F, 0x6F, "OperatingSystemStatus"},
    {0x12, 0x6F, "SYSTEM_EVENT"},
    {0xC7, 0x03, "SYSTEM"},
    {0xC7, 0x03, "MAIN_PLANAR"},
    {0xC2, 0x6F, "PowerCap"},
    {0xFF, 0x00, ""},
};


struct sensor_data_t {
    uint8_t sennum;
}  __attribute__ ((packed)) ;

struct sensorreadingresp_t {
    uint8_t value;
    uint8_t operation;
    uint8_t indication[2];
}  __attribute__ ((packed)) ;

uint8_t dbus_to_sensor_type(char *p) {

    sensorTypemap_t *s = g_SensorTypeMap;
    char r=0;

    while (s->number != 0xFF) {
        if (!strcmp(s->dbusname,p)) {
            r = s->number;
             break;
        }
        s++;
    }


    if (s->number == 0xFF)
        printf("Failed to find Sensor Type %s\n", p);

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

    // This is where sensors that do not exist in dbus but do
    // exist in the host code stop.  This should indicate it
    // is not a supported sensor
    if (a.interface[0] == 0) { return 0;}

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

    // HACK UNTIL Dbus gets updated or we find a better way
    if (buf[0] == 0) {
        rc = IPMI_CC_SENSOR_INVALID;
    }


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

    printf("IPMI SET_SENSOR [0x%02x]\n",reqptr->sennum);

    updateSensorRecordFromSSRAESC(reqptr);

    *data_len=0;

    return rc;
}


ipmi_ret_t ipmi_sen_get_sensor_reading(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    sensor_data_t *reqptr = (sensor_data_t*)request;
    ipmi_ret_t rc = IPMI_CC_SENSOR_INVALID;
    uint8_t type;
    sensorreadingresp_t *resp = (sensorreadingresp_t*) response;
    int r;
    dbus_interface_t a;
    sd_bus *bus = ipmid_get_sd_bus_connection();
    sd_bus_message *reply = NULL;
    uint8_t reading;


    printf("IPMI GET_SENSOR_READING [0x%02x]\n",reqptr->sennum);

    r = find_openbmc_path("SENSOR", reqptr->sennum, &a);

    type = find_sensor(reqptr->sennum);

    fprintf(stderr, "Bus: %s, Path: %s, Interface: %s\n", a.bus, a.path, a.interface);

    *data_len=0;

    switch(type) {
        case 0xC3:
        case 0xC2:
            r = sd_bus_get_property(bus,a.bus, a.path, a.interface, "value", NULL, &reply, "y");
            if (r < 0) {
                fprintf(stderr, "Failed to call sd_bus_get_property:%d,  %s\n", r, strerror(-r));
                fprintf(stderr, "Bus: %s, Path: %s, Interface: %s\n",
                        a.bus, a.path, a.interface);
                break;
            }

            r = sd_bus_message_read(reply, "y", &reading);
            if (r < 0) {
                fprintf(stderr, "Failed to read byte: %s\n", strerror(-r));
                break;
            }

            printf("Contents of a 0x%02x is 0x%02x\n", type, reading);

            rc = IPMI_CC_OK;
            *data_len=sizeof(sensorreadingresp_t);

            resp->value         = reading;
            resp->operation     = 0;
            resp->indication[0] = 0;
            resp->indication[1] = 0;
            break;

        default:
            *data_len=0;
            rc = IPMI_CC_SENSOR_INVALID;
            break;
    }


    reply = sd_bus_message_unref(reply);

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

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_SENSOR, IPMI_CMD_GET_SENSOR_READING);
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_GET_SENSOR_READING, NULL, ipmi_sen_get_sensor_reading);

    return;
}
