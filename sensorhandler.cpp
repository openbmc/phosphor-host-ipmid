#include <mapper.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <set>
#include <bitset>
#include <xyz/openbmc_project/Sensor/Value/server.hpp>
#include <systemd/sd-bus.h>
#include "host-ipmid/ipmid-api.h"
#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include "ipmid.hpp"
#include "sensorhandler.h"
#include "types.hpp"
#include "utils.hpp"
#include "xyz/openbmc_project/Common/error.hpp"

extern int updateSensorRecordFromSSRAESC(const void *);
extern sd_bus *bus;
extern const ipmi::sensor::IdInfoMap sensors;
using namespace phosphor::logging;
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

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
    {0x0b, 0xCA, "PowerSupplyRedundancy"},
    {0xDA, 0x03, "TurboAllowed"},
    {0xD8, 0xC8, "PowerSupplyDerating"},
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

int get_bus_for_path(const char *path, char **busname) {
    return mapper_get_service(bus, path, busname);
}

int legacy_dbus_openbmc_path(const char *type, const uint8_t num, dbus_interface_t *interface) {
    char  *busname = NULL;
    const char  *iface = "org.openbmc.managers.System";
    const char  *objname = "/org/openbmc/managers/System";
    char  *str1 = NULL, *str2, *str3;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = NULL;


    int r;
    r = get_bus_for_path(objname, &busname);
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

    r = get_bus_for_path(str2, &str1);
    if (r < 0) {
        fprintf(stderr, "Failed to get %s busname: %s\n",
                str2, strerror(-r));
        goto final;
    }

    strncpy(interface->bus, str1, MAX_DBUS_PATH);
    strncpy(interface->path, str2, MAX_DBUS_PATH);
    strncpy(interface->interface, str3, MAX_DBUS_PATH);

    interface->sensornumber = num;
    // Make sure we know that the type hasn't been set, as newer codebase will
    // set it automatically from the YAML at this step.
    interface->sensortype = 0;

final:

    sd_bus_error_free(&error);
    reply = sd_bus_message_unref(reply);
    free(busname);
    free(str1);

    return r;
}

// Use a lookup table to find the interface name of a specific sensor
// This will be used until an alternative is found.  this is the first
// step for mapping IPMI
int find_openbmc_path(uint8_t num, dbus_interface_t *interface) {
    int rc;

    // When the sensor map does not contain the sensor requested,
    // fall back to the legacy DBus lookup (deprecated)
    const auto& sensor_it = sensors.find(num);
    if (sensor_it == sensors.end())
    {
        return legacy_dbus_openbmc_path("SENSOR", num, interface);
    }

    const auto& info = sensor_it->second;

    char* busname = nullptr;
    rc = get_bus_for_path(info.sensorPath.c_str(), &busname);
    if (rc < 0) {
        fprintf(stderr, "Failed to get %s busname: %s\n",
                info.sensorPath.c_str(),
                busname);
        goto final;
    }

    interface->sensortype = info.sensorType;
    strcpy(interface->bus, busname);
    strcpy(interface->path, info.sensorPath.c_str());
    // Take the interface name from the beginning of the DbusInterfaceMap. This
    // works for the Value interface but may not suffice for more complex
    // sensors.
    // tracked https://github.com/openbmc/phosphor-host-ipmid/issues/103
    strcpy(interface->interface, info.propertyInterfaces.begin()->first.c_str());
    interface->sensornumber = num;

final:
    free(busname);
    return rc;
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

    r = find_openbmc_path(number, &a);

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

    r = find_openbmc_path(number, &a);

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
            r = s->typecode;
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

uint8_t get_type_from_interface(dbus_interface_t dbus_if) {

    char *p;
    uint8_t type;

    // This is where sensors that do not exist in dbus but do
    // exist in the host code stop.  This should indicate it
    // is not a supported sensor
    if (dbus_if.interface[0] == 0) { return 0;}

    // Fetch type from interface itself.
    if (dbus_if.sensortype != 0)
    {
        type = dbus_if.sensortype;
    }
    // Legacy codebase does not populate type during initial handling:
    else if (strstr(dbus_if.interface, "InventoryItem")) {
        // InventoryItems are real frus.  So need to get the
        // fru_type property
        type = dbus_to_sensor_type_from_dbus(&dbus_if);
    } else {
        // Non InventoryItems
        p = strrchr (dbus_if.path, '/');
        type = dbus_to_sensor_type(p+1);
    }

    return type;
 }

// Replaces find_sensor
uint8_t find_type_for_sensor_number(uint8_t num) {
    int r;
    dbus_interface_t dbus_if;
    r = find_openbmc_path(num, &dbus_if);
    if (r < 0) {
        fprintf(stderr, "Could not find sensor %d\n", num);
        return r;
    }
    return get_type_from_interface(dbus_if);
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

    buf[0] = find_type_for_sensor_number(reqptr->sennum);

    // HACK UNTIL Dbus gets updated or we find a better way
    if (buf[0] == 0) {
        rc = IPMI_CC_SENSOR_INVALID;
    }


    *data_len = sizeof(buf);
    memcpy(response, &buf, *data_len);

    return rc;
}

const std::set<std::string> analogSensorInterfaces =
{
    "xyz.openbmc_project.Sensor.Value",
};

bool isAnalogSensor(const std::string& interface)
{
    return (analogSensorInterfaces.count(interface));
}

ipmi_ret_t setSensorReading(void *request)
{
    ipmi::sensor::SetSensorReadingReq cmdData =
            *(static_cast<ipmi::sensor::SetSensorReadingReq *>(request));

    // Check if the Sensor Number is present
    const auto iter = sensors.find(cmdData.number);
    if (iter == sensors.end())
    {
        return IPMI_CC_SENSOR_INVALID;
    }

    try
    {
        return iter->second.updateFunc(cmdData, iter->second);
    }
    catch (InternalFailure& e)
    {
         log<level::ERR>("Set sensor failed",
                         entry("SENSOR_NUM=%d", cmdData.number));
         commit<InternalFailure>();
    }
    catch (const std::runtime_error& e)
    {
        log<level::ERR>(e.what());
    }

    return IPMI_CC_UNSPECIFIED_ERROR;
}

ipmi_ret_t ipmi_sen_set_sensor(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    sensor_data_t *reqptr = (sensor_data_t*)request;

    printf("IPMI SET_SENSOR [0x%02x]\n",reqptr->sennum);

    /*
     * This would support the Set Sensor Reading command for the presence
     * and functional state of Processor, Core & DIMM. For the remaining
     * sensors the existing support is invoked.
     */
    auto ipmiRC = setSensorReading(request);

    if(ipmiRC == IPMI_CC_SENSOR_INVALID)
    {
        updateSensorRecordFromSSRAESC(reqptr);
        ipmiRC = IPMI_CC_OK;
    }

    *data_len=0;
    return ipmiRC;
}


ipmi_ret_t ipmi_sen_get_sensor_reading(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    sensor_data_t *reqptr = (sensor_data_t*)request;
    ipmi_ret_t rc = IPMI_CC_SENSOR_INVALID;
    uint8_t type = 0;
    sensorreadingresp_t *resp = (sensorreadingresp_t*) response;
    int r;
    dbus_interface_t a;
    sd_bus *bus = ipmid_get_sd_bus_connection();
    sd_bus_message *reply = NULL;
    int reading = 0;
    char* assertion = NULL;
    ipmi::sensor::GetSensorResponse getResponse {};
    static constexpr auto scanningEnabledBit = 6;

    printf("IPMI GET_SENSOR_READING [0x%02x]\n",reqptr->sennum);

    r = find_openbmc_path(reqptr->sennum, &a);

    if (r < 0)
    {
        fprintf(stderr, "Failed to find Sensor 0x%02x\n", reqptr->sennum);
    }
    else
    {
        type = get_type_from_interface(a);
        if(type == 0) {
            fprintf(stderr, "Failed to find Sensor 0x%02x\n", reqptr->sennum);
            return IPMI_CC_SENSOR_INVALID;
        }

        fprintf(stderr, "Bus: %s, Path: %s, Interface: %s\n", a.bus, a.path,
                        a.interface);
    }

    *data_len=0;

    int64_t raw_value;
    ipmi::sensor::Info sensor;

    switch(type) {
        case 0xC2:
        case 0xC8:
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

        //TODO openbmc/openbmc#2154 Move this sensor to right place.
        case 0xCA:
            r = sd_bus_get_property(bus,a.bus, a.path, a.interface, "value", NULL, &reply, "s");
            if (r < 0) {
                fprintf(stderr, "Failed to call sd_bus_get_property:%d,  %s\n", r, strerror(-r));
                fprintf(stderr, "Bus: %s, Path: %s, Interface: %s\n",
                        a.bus, a.path, a.interface);
                break;
            }

            r = sd_bus_message_read(reply, "s", &assertion);
            if (r < 0) {
                fprintf(stderr, "Failed to read sensor: %s\n", strerror(-r));
                break;
            }

            rc = IPMI_CC_OK;
            *data_len=sizeof(sensorreadingresp_t);

            resp->value         = 0;
            resp->operation     = 0;
            if (strcmp(assertion,"Enabled") == 0)
            {
                resp->indication[0] = 0x02;
            }
            else
            {
                resp->indication[0] = 0x1;
            }
            resp->indication[1] = 0;
            break;

        case IPMI_SENSOR_TEMP:
        case IPMI_SENSOR_VOLTAGE:
        case IPMI_SENSOR_CURRENT:
        case IPMI_SENSOR_FAN:
            // Get reading for /xyz/openbmc_project/Sensor/Value.interface
            if(sensors.find(reqptr->sennum) == sensors.end())
            {
                fprintf(stderr, "Failed to find config entry for Sensor 0x%02x\n",
                        reqptr->sennum);
                return IPMI_CC_SENSOR_INVALID;
            }

            sensor = sensors.at(reqptr->sennum);
            if (ipmi::sensor::Mutability::Read !=
                  (sensor.mutability & ipmi::sensor::Mutability::Read))
            {
                log<level::ERR>("Sensor was not readable.\n");
                return IPMI_CC_SENSOR_INVALID;
            }


            // Get value
            r = sd_bus_get_property_trivial(bus,
                                            a.bus,
                                            a.path,
                                            a.interface,
                                            "Value",
                                            NULL,
                                            'x',
                                            &raw_value);
            if (r < 0) {
                fprintf(stderr,
                        "Failed to call sd_bus_get_property:%d,  %s, 'value'\n",
                        r,
                        strerror(-r));
                fprintf(stderr, "Bus: %s, Path: %s, Interface: %s\n",
                        a.bus, a.path, a.interface);
                break;
            }

            // Prevent div0
            if (sensor.coefficientM == 0) {
                sensor.coefficientM = 1;
            };

            resp->value = static_cast<uint8_t>(
                    (raw_value - sensor.scaledOffset) / sensor.coefficientM);
            resp->operation = 1 << scanningEnabledBit; // scanning enabled
            resp->indication[0] = 0; // not a threshold sensor. ignore
            resp->indication[1] = 0;
            rc = IPMI_CC_OK;
            *data_len=sizeof(sensorreadingresp_t);
            break;
        default:
        {
            const auto iter = sensors.find(reqptr->sennum);
            if (iter == sensors.end())
            {
                return IPMI_CC_SENSOR_INVALID;
            }

            try
            {
                getResponse =  iter->second.getFunc(iter->second);
                *data_len = getResponse.size();
                memcpy(resp, getResponse.data(), *data_len);
                resp->operation = 1 << scanningEnabledBit;
                return IPMI_CC_OK;
            }
            catch (InternalFailure& e)
            {
                *data_len = getResponse.size();
                memcpy(resp, getResponse.data(), *data_len);
                return IPMI_CC_OK;
            }
            catch (const std::runtime_error& e)
            {
                *data_len = getResponse.size();
                memcpy(resp, getResponse.data(), *data_len);
                return IPMI_CC_OK;
            }
        }
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

ipmi_ret_t ipmi_sen_get_sdr_info(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                 ipmi_request_t request,
                                 ipmi_response_t response,
                                 ipmi_data_len_t data_len,
                                 ipmi_context_t context)
{
    auto resp = static_cast<get_sdr_info::GetSdrInfoResp*>(response);
    if (request == nullptr ||
        get_sdr_info::request::get_count(request) == false)
    {
        // Get Sensor Count
        resp->count = sensors.size();
    }
    else
    {
        resp->count = 1;
    }

    // Multiple LUNs not supported.
    namespace response = get_sdr_info::response;
    response::set_lun_present(0, &(resp->luns_and_dynamic_population));
    response::set_lun_not_present(1, &(resp->luns_and_dynamic_population));
    response::set_lun_not_present(2, &(resp->luns_and_dynamic_population));
    response::set_lun_not_present(3, &(resp->luns_and_dynamic_population));
    response::set_static_population(&(resp->luns_and_dynamic_population));

    *data_len = SDR_INFO_RESP_SIZE;

    return IPMI_CC_OK;
}

ipmi_ret_t ipmi_sen_reserve_sdr(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request,
                                ipmi_response_t response,
                                ipmi_data_len_t data_len,
                                ipmi_context_t context)
{
    // A constant reservation ID is okay until we implement add/remove SDR.
    const uint16_t reservation_id = 1;
    *(uint16_t*)response = reservation_id;
    *data_len = sizeof(uint16_t);

    printf("Created new IPMI SDR reservation ID %d\n", *(uint16_t*)response);
    return IPMI_CC_OK;
}

void setUnitFieldsForObject(sd_bus *bus,
                            const dbus_interface_t &iface,
                            const ipmi::sensor::Info *info,
                            get_sdr::SensorDataFullRecordBody *body)
{
    if (info->propertyInterfaces.begin()->first ==
        "xyz.openbmc_project.Sensor.Value")
    {
        std::string result {};
        if (info->unit.empty())
        {
            char *raw_cstr = NULL;
            if (0 > sd_bus_get_property_string(bus, iface.bus, iface.path,
                                               iface.interface, "Unit", NULL,
                                               &raw_cstr))
            {
                log<level::WARNING>("Unit interface missing.",
                                    entry("BUS=%s", iface.bus),
                                    entry("PATH=%s", iface.path));
            }
            else
            {
                result = raw_cstr;
            }
            free(raw_cstr);
        }
        else
        {
            result = info->unit;
        }

        namespace server = sdbusplus::xyz::openbmc_project::Sensor::server;
        try {
            auto unit = server::Value::convertUnitFromString(result);
            // Unit strings defined in
            // phosphor-dbus-interfaces/xyz/openbmc_project/Sensor/Value.interface.yaml
            switch (unit)
            {
                case server::Value::Unit::DegreesC:
                    body->sensor_units_2_base = get_sdr::SENSOR_UNIT_DEGREES_C;
                    break;
                case server::Value::Unit::RPMS:
                    body->sensor_units_2_base = get_sdr::SENSOR_UNIT_REVOLUTIONS; // revolutions
                    get_sdr::body::set_rate_unit(0b100, body); // per minute
                    break;
                case server::Value::Unit::Volts:
                    body->sensor_units_2_base = get_sdr::SENSOR_UNIT_VOLTS;
                    break;
                case server::Value::Unit::Meters:
                    body->sensor_units_2_base = get_sdr::SENSOR_UNIT_METERS;
                    break;
                case server::Value::Unit::Amperes:
                    body->sensor_units_2_base = get_sdr::SENSOR_UNIT_AMPERES;
                    break;
                case server::Value::Unit::Joules:
                    body->sensor_units_2_base = get_sdr::SENSOR_UNIT_JOULES;
                    break;
                default:
                    // Cannot be hit.
                    fprintf(stderr, "Unknown value unit type: = %s\n", result.c_str());
            }
        }
        catch (sdbusplus::exception::InvalidEnumString e)
        {
            log<level::WARNING>("Warning: no unit provided for sensor!");
        }
    }
}

int64_t getScaleForObject(sd_bus *bus,
                          const dbus_interface_t& iface,
                          const ipmi::sensor::Info *info)
{
    int64_t result = 0;
    if (info->propertyInterfaces.begin()->first ==
        "xyz.openbmc_project.Sensor.Value")
    {
        if (info->hasScale)
        {
            result = info->scale;
        }
        else
        {
            if (0 > sd_bus_get_property_trivial(bus,
                                                iface.bus,
                                                iface.path,
                                                iface.interface,
                                                "Scale",
                                                NULL,
                                                'x',
                                                &result)) {
                log<level::WARNING>("Scale interface missing.",
                                    entry("BUS=%s", iface.bus),
                                    entry("PATH=%s", iface.path));
            }
        }
    }

    return result;
}

ipmi_ret_t populate_record_from_dbus(get_sdr::SensorDataFullRecordBody *body,
                                     const ipmi::sensor::Info *info,
                                     ipmi_data_len_t data_len)
{
    /* Functional sensor case */
    if (isAnalogSensor(info->propertyInterfaces.begin()->first))
    {
        // Get bus
        sd_bus *bus = ipmid_get_sd_bus_connection();
        dbus_interface_t iface;

        if (0 > find_openbmc_path(body->entity_id, &iface))
            return IPMI_CC_SENSOR_INVALID;

        body->sensor_units_1 = 0; // unsigned, no rate, no modifier, not a %

        /* Unit info */
        setUnitFieldsForObject(bus, iface, info, body);

        /* Modifiers to reading info */
        // Get scale
        int64_t scale = getScaleForObject(bus, iface, info);

        get_sdr::body::set_b(info->coefficientB, body);
        get_sdr::body::set_m(info->coefficientM, body);
        get_sdr::body::set_b_exp(info->exponentB, body);
        get_sdr::body::set_r_exp(scale, body);

        get_sdr::body::set_id_type(0b00, body); // 00 = unicode
    }

    /* ID string */
    auto id_string = info->sensorNameFunc(*info);

    if (id_string.length() > FULL_RECORD_ID_STR_MAX_LENGTH)
    {
        get_sdr::body::set_id_strlen(FULL_RECORD_ID_STR_MAX_LENGTH, body);
    }
    else
    {
        get_sdr::body::set_id_strlen(id_string.length(), body);
    }
    strncpy(body->id_string, id_string.c_str(),
            get_sdr::body::get_id_strlen(body));

    return IPMI_CC_OK;
};

ipmi_ret_t ipmi_sen_get_sdr(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                            ipmi_request_t request, ipmi_response_t response,
                            ipmi_data_len_t data_len, ipmi_context_t context)
{
    ipmi_ret_t ret = IPMI_CC_OK;
    get_sdr::GetSdrReq *req = (get_sdr::GetSdrReq*)request;
    get_sdr::GetSdrResp *resp = (get_sdr::GetSdrResp*)response;
    get_sdr::SensorDataFullRecord record = {0};
    if (req != NULL)
    {
        // Note: we use an iterator so we can provide the next ID at the end of
        // the call.
        auto sensor = sensors.begin();

        // At the beginning of a scan, the host side will send us id=0.
        if (get_sdr::request::get_record_id(req) != 0)
        {
            sensor = sensors.find(get_sdr::request::get_record_id(req));
            if(sensor == sensors.end()) {
                return IPMI_CC_SENSOR_INVALID;
            }
        }

        uint8_t sensor_id = sensor->first;

        /* Header */
        get_sdr::header::set_record_id(sensor_id, &(record.header));
        record.header.sdr_version = 0x51; // Based on IPMI Spec v2.0 rev 1.1
        record.header.record_type = get_sdr::SENSOR_DATA_FULL_RECORD;
        record.header.record_length = sizeof(get_sdr::SensorDataFullRecord);

        /* Key */
        get_sdr::key::set_owner_id_bmc(&(record.key));
        record.key.sensor_number = sensor_id;

        /* Body */
        record.body.entity_id = sensor->second.entityType;
        record.body.sensor_type = sensor->second.sensorType;
        record.body.event_reading_type = sensor->second.sensorReadingType;
        record.body.entity_instance = sensor->second.instance;

        // Set the type-specific details given the DBus interface
        ret = populate_record_from_dbus(&(record.body), &(sensor->second),
                                        data_len);

        if (++sensor == sensors.end())
        {
            get_sdr::response::set_next_record_id(0xFFFF, resp); // last record
        }
        else
        {
            get_sdr::response::set_next_record_id(sensor->first, resp);
        }

        *data_len = sizeof(get_sdr::GetSdrResp) - req->offset;
        memcpy(resp->record_data, (char*)&record + req->offset,
               sizeof(get_sdr::SensorDataFullRecord) - req->offset);
    }

    return ret;
}


void register_netfn_sen_functions()
{
    // <Wildcard Command>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",
           NETFUN_SENSOR, IPMI_CMD_WILDCARD);
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_WILDCARD,
                           nullptr, ipmi_sen_wildcard,
                           PRIVILEGE_USER);

    // <Get Sensor Type>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",
           NETFUN_SENSOR, IPMI_CMD_GET_SENSOR_TYPE);
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_GET_SENSOR_TYPE,
                           nullptr, ipmi_sen_get_sensor_type,
                           PRIVILEGE_USER);

    // <Set Sensor Reading and Event Status>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",
           NETFUN_SENSOR, IPMI_CMD_SET_SENSOR);
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_SET_SENSOR,
                           nullptr, ipmi_sen_set_sensor,
                           PRIVILEGE_OPERATOR);

    // <Get Sensor Reading>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",
           NETFUN_SENSOR, IPMI_CMD_GET_SENSOR_READING);
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_GET_SENSOR_READING,
                           nullptr, ipmi_sen_get_sensor_reading,
                           PRIVILEGE_USER);

    // <Reserve SDR>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",
           NETFUN_SENSOR, IPMI_CMD_RESERVE_SDR_REPO);
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_RESERVE_SDR_REPO,
                           nullptr, ipmi_sen_reserve_sdr,
                           PRIVILEGE_USER);

    // <Get SDR Info>
    printf("Registering NetFn:[0x%X], Cmd:[0x%x]\n",
           NETFUN_SENSOR, IPMI_CMD_GET_SDR_INFO);
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_GET_SDR_INFO,
                           nullptr, ipmi_sen_get_sdr_info,
                           PRIVILEGE_USER);

    // <Get SDR>
    printf("Registering NetFn:[0x%X], Cmd:[0x%x]\n",
           NETFUN_SENSOR, IPMI_CMD_GET_SDR);
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_GET_SDR,
                           nullptr, ipmi_sen_get_sdr,
                           PRIVILEGE_USER);

    return;
}
