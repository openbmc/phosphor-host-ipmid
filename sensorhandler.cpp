#include <mapper.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <bitset>
#include <iostream>
#include <systemd/sd-bus.h>
#include "host-ipmid/ipmid-api.h"
#include "ipmid.hpp"
#include "sensorhandler.h"
#include "types.hpp"
#include "utils.hpp"

extern int updateSensorRecordFromSSRAESC(const void *);
extern sd_bus *bus;
extern const ipmi::sensor::IDInfoMap sensors;

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

// Use a lookup table to find the interface name of a specific sensor
// This will be used until an alternative is found.  this is the first
// step for mapping IPMI
int find_interface_property_fru_type(dbus_interface_t *interface, const char *property_name, char *property_value) {

    char  *str1;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = NULL, *m=NULL;


    int r;

    r = sd_bus_message_new_method_call(bus,&m,interface->bus,interface->path,"org.freedesktop.DBus.Properties","Get");
    if (r < 0) {
        fprintf(stderr, "Failed to create a method call: %s", strerror(-r));
        fprintf(stderr,"Bus: %s Path: %s Interface: %s \n",
                interface->bus, interface->path, interface->interface);
        goto final;
    }

    r = sd_bus_message_append(m, "ss", "org.openbmc.InventoryItem", property_name);
    if (r < 0) {
        fprintf(stderr, "Failed to create a input parameter: %s", strerror(-r));
        fprintf(stderr,"Bus: %s Path: %s Interface: %s \n",
                interface->bus, interface->path, interface->interface);
        goto final;
    }

    r = sd_bus_call(bus, m, 0, &error, &reply);
    if (r < 0) {
        fprintf(stderr, "Failed to call the method: %s", strerror(-r));
        goto final;
    }

    r = sd_bus_message_read(reply, "v",  "s", &str1) ;
    if (r < 0) {
        fprintf(stderr, "Failed to get a response: %s", strerror(-r));
        goto final;
    }

    strcpy(property_value, str1);

final:

    sd_bus_error_free(&error);
    m = sd_bus_message_unref(m);
    reply = sd_bus_message_unref(reply);

    return r;
}


// Use a lookup table to find the interface name of a specific sensor
// This will be used until an alternative is found.  this is the first
// step for mapping IPMI
int find_openbmc_path(const char *type, const uint8_t num, dbus_interface_t *interface) {
    char  *busname = NULL;
    const char  *iface = "org.openbmc.managers.System";
    const char  *objname = "/org/openbmc/managers/System";
    char  *str1 = NULL, *str2, *str3;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = NULL;


    int r;
    r = mapper_get_service(bus, objname, &busname);
    if (r < 0) {
        fprintf(stderr, "Failed to get %s busname: %s\n",
                objname, strerror(-r));
        goto final;
    }

    r = sd_bus_call_method(bus,busname,objname,iface, "getObjectFromByteId",
                           &error, &reply, "sy", type, num);
    if (r < 0) {
        fprintf(stderr, "Failed to create a method call: %s", strerror(-r));
        goto final;
    }

    r = sd_bus_message_read(reply, "(ss)", &str2, &str3);
    if (r < 0) {
        fprintf(stderr, "Failed to get a response: %s", strerror(-r));
        goto final;
    }

    r = mapper_get_service(bus, str2, &str1);
    if (r < 0) {
        fprintf(stderr, "Failed to get %s busname: %s\n",
                str2, strerror(-r));
        goto final;
    }

    strncpy(interface->bus, str1, MAX_DBUS_PATH);
    strncpy(interface->path, str2, MAX_DBUS_PATH);
    strncpy(interface->interface, str3, MAX_DBUS_PATH);

    interface->sensornumber = num;

final:

    sd_bus_error_free(&error);
    reply = sd_bus_message_unref(reply);
    free(busname);
    free(str1);

    return r;
}


/////////////////////////////////////////////////////////////////////
//
// Routines used by ipmi commands wanting to interact on the dbus
//
/////////////////////////////////////////////////////////////////////
int set_sensor_dbus_state_s(uint8_t number, const char *method, const char *value) {


    dbus_interface_t a;
    int r;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *m=NULL;

    fprintf(ipmidbus, "Attempting to set a dbus Variant Sensor 0x%02x via %s with a value of %s\n",
        number, method, value);

    r = find_openbmc_path("SENSOR", number, &a);

    if (r < 0) {
        fprintf(stderr, "Failed to find Sensor 0x%02x\n", number);
        return 0;
    }

    r = sd_bus_message_new_method_call(bus,&m,a.bus,a.path,a.interface,method);
    if (r < 0) {
        fprintf(stderr, "Failed to create a method call: %s", strerror(-r));
        goto final;
    }

    r = sd_bus_message_append(m, "v", "s", value);
    if (r < 0) {
        fprintf(stderr, "Failed to create a input parameter: %s", strerror(-r));
        goto final;
    }


    r = sd_bus_call(bus, m, 0, &error, NULL);
    if (r < 0) {
        fprintf(stderr, "Failed to call the method: %s", strerror(-r));
    }

final:
    sd_bus_error_free(&error);
    m = sd_bus_message_unref(m);

    return 0;
}
int set_sensor_dbus_state_y(uint8_t number, const char *method, const uint8_t value) {


    dbus_interface_t a;
    int r;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *m=NULL;

    fprintf(ipmidbus, "Attempting to set a dbus Variant Sensor 0x%02x via %s with a value of 0x%02x\n",
        number, method, value);

    r = find_openbmc_path("SENSOR", number, &a);

    if (r < 0) {
        fprintf(stderr, "Failed to find Sensor 0x%02x\n", number);
        return 0;
    }

    r = sd_bus_message_new_method_call(bus,&m,a.bus,a.path,a.interface,method);
    if (r < 0) {
        fprintf(stderr, "Failed to create a method call: %s", strerror(-r));
        goto final;
    }

    r = sd_bus_message_append(m, "v", "i", value);
    if (r < 0) {
        fprintf(stderr, "Failed to create a input parameter: %s", strerror(-r));
        goto final;
    }


    r = sd_bus_call(bus, m, 0, &error, NULL);
    if (r < 0) {
        fprintf(stderr, "12 Failed to call the method: %s", strerror(-r));
    }

final:
    sd_bus_error_free(&error);
    m = sd_bus_message_unref(m);

    return 0;
}

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
    int r;
    uint8_t type;

    r = find_openbmc_path("SENSOR", sensor_number, &a);

    if (r < 0) { return 0; }

    // This is where sensors that do not exist in dbus but do
    // exist in the host code stop.  This should indicate it
    // is not a supported sensor
    if (a.interface[0] == 0) { return 0;}

    if (strstr(a.interface, "InventoryItem")) {
        // InventoryItems are real frus.  So need to get the
        // fru_type property
        type = dbus_to_sensor_type_from_dbus(&a);
    } else {
        // Non InventoryItems
        p = strrchr (a.path, '/');
        type = dbus_to_sensor_type(p+1);
    }

    return type;
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

ipmi_ret_t setSensorReading(void *request)
{
    auto cmdData = static_cast<SetSensorReadingReq *>(request);

    auto assertionStates =
            (static_cast<uint16_t>(cmdData->assertOffset8_14)) << 8 |
            cmdData->assertOffset0_7;

    auto deassertionStates =
            (static_cast<uint16_t>(cmdData->deassertOffset8_14)) << 8 |
            cmdData->deassertOffset0_7;

    std::bitset<16> assertionSet(assertionStates);
    std::bitset<16> deassertionSet(deassertionStates);

    // Check if the Sensor Number is present
    auto iter = sensors.find(cmdData->number);
    if (iter == sensors.end())
    {
        return IPMI_CC_SENSOR_INVALID;
    }

    auto interfaceList = iter->second.sensorInterfaces;
    if (interfaceList.size() <= 0)
    {
        std::cerr << "Interface List empty for this Sensor="
                  << cmdData->number << "\n";
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    ipmi::sensor::ObjectMap objects;
    for (auto& interface : interfaceList)
    {
        ipmi::sensor::InterfaceMap interfaces;
        for (auto& property : interface.second)
        {
            ipmi::sensor::PropertyMap props;
            for (auto& value : property.second)
            {
                if (assertionSet.test(value.first))
                {
                    props.emplace(property.first, value.second.assert);
                    assertionSet.reset(value.first);
                }
                else if (deassertionSet.test(value.first))
                {
                    props.emplace(property.first, value.second.deassert);
                    deassertionSet.reset(value.first);
                }
            }
            interfaces.emplace(interface.first, props);
        }
        sdbusplus::message::object_path path = iter->second.sensorPath;
        objects.emplace(std::move(path), interfaces);
    }

    auto bus = sdbusplus::bus::new_default();
    using namespace std::string_literals;
    static const auto intf = "xyz.openbmc_project.Inventory.Manager"s;
    static const auto path = "/xyz/openbmc_project/inventory"s;
    std::string service;

    try
    {
        service = getService(bus, intf, path);
    }
    catch (const std::runtime_error& e)
    {
        std::cerr << e.what() << "\n";
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    // Update the inventory manager
    auto pimMsg = bus.new_method_call(service.c_str(),
                                      path.c_str(),
                                      intf.c_str(),
                                      "Notify");
    pimMsg.append(std::move(objects));
    auto inventoryMgrResponseMsg = bus.call(pimMsg);
    if (inventoryMgrResponseMsg.is_method_error())
    {
        std::cerr << "Error in notify call\n";
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    return IPMI_CC_OK;
}

ipmi_ret_t ipmi_sen_set_sensor(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    sensor_data_t *reqptr = (sensor_data_t*)request;
    ipmi_ret_t rc = IPMI_CC_OK;

    printf("IPMI SET_SENSOR [0x%02x]\n",reqptr->sennum);

    auto ipmiRC = setSensorReading(request);

    if(ipmiRC == IPMI_CC_SENSOR_INVALID)
    {
        updateSensorRecordFromSSRAESC(reqptr);
    }

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
    int reading = 0;


    printf("IPMI GET_SENSOR_READING [0x%02x]\n",reqptr->sennum);

    r = find_openbmc_path("SENSOR", reqptr->sennum, &a);

    if (r < 0) {
        fprintf(stderr, "Failed to find Sensor 0x%02x\n", reqptr->sennum);
        return IPMI_CC_SENSOR_INVALID;
    }

    type = find_sensor(reqptr->sennum);
    if(type == 0) {
        fprintf(stderr, "Failed to find Sensor 0x%02x\n", reqptr->sennum);
        return IPMI_CC_SENSOR_INVALID;
    }

    fprintf(stderr, "Bus: %s, Path: %s, Interface: %s\n", a.bus, a.path, a.interface);

    *data_len=0;

    switch(type) {
        case 0xC3:
        case 0xC2:
            r = sd_bus_get_property(bus,a.bus, a.path, a.interface, "value", NULL, &reply, "i");
            if (r < 0) {
                fprintf(stderr, "Failed to call sd_bus_get_property:%d,  %s\n", r, strerror(-r));
                fprintf(stderr, "Bus: %s, Path: %s, Interface: %s\n",
                        a.bus, a.path, a.interface);
                break;
            }

            r = sd_bus_message_read(reply, "i", &reading);
            if (r < 0) {
                fprintf(stderr, "Failed to read sensor: %s\n", strerror(-r));
                break;
            }

            printf("Contents of a 0x%02x is 0x%02x\n", type, reading);

            rc = IPMI_CC_OK;
            *data_len=sizeof(sensorreadingresp_t);

            resp->value         = (uint8_t)reading;
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
    ipmi_ret_t rc = IPMI_CC_INVALID;

    printf("IPMI S/E Wildcard Netfn:[0x%X], Cmd:[0x%X]\n",netfn,cmd);
    *data_len = 0;

    return rc;
}


void register_netfn_sen_functions()
{
    // <Wildcard Command>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_SENSOR, IPMI_CMD_WILDCARD);
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_WILDCARD, NULL, ipmi_sen_wildcard,
                           PRIVILEGE_USER);

    // <Get Sensor Type>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_SENSOR, IPMI_CMD_GET_SENSOR_TYPE);
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_GET_SENSOR_TYPE, NULL, ipmi_sen_get_sensor_type,
                           PRIVILEGE_USER);

    // <Set Sensor Reading and Event Status>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_SENSOR, IPMI_CMD_SET_SENSOR);
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_SET_SENSOR, NULL, ipmi_sen_set_sensor,
                           PRIVILEGE_OPERATOR);

    // <Get Sensor Reading>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_SENSOR, IPMI_CMD_GET_SENSOR_READING);
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_GET_SENSOR_READING, NULL,
                           ipmi_sen_get_sensor_reading, PRIVILEGE_USER);

    return;
}
