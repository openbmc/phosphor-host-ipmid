#include "sensorhandler.hpp"

#include "fruread.hpp"

#include <mapper.h>
#include <systemd/sd-bus.h>

#include <bitset>
#include <cmath>
#include <cstring>
#include <ipmid/api.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/message/types.hpp>
#include <set>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/Sensor/Value/server.hpp>

static constexpr uint8_t fruInventoryDevice = 0x10;
static constexpr uint8_t IPMIFruInventory = 0x02;
static constexpr uint8_t BMCSlaveAddress = 0x20;

extern int updateSensorRecordFromSSRAESC(const void*);
extern sd_bus* bus;
extern const ipmi::sensor::IdInfoMap sensors;
extern const FruMap frus;
extern const ipmi::sensor::EntityInfoMap entities;

using namespace phosphor::logging;
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

void register_netfn_sen_functions() __attribute__((constructor));

struct sensorTypemap_t
{
    uint8_t number;
    uint8_t typecode;
    char dbusname[32];
};

sensorTypemap_t g_SensorTypeMap[] = {

    {0x01, 0x6F, "Temp"},
    {0x0C, 0x6F, "DIMM"},
    {0x0C, 0x6F, "MEMORY_BUFFER"},
    {0x07, 0x6F, "PROC"},
    {0x07, 0x6F, "CORE"},
    {0x07, 0x6F, "CPU"},
    {0x0F, 0x6F, "BootProgress"},
    {0xe9, 0x09, "OccStatus"}, // E9 is an internal mapping to handle sensor
                               // type code os 0x09
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

struct sensor_data_t
{
    uint8_t sennum;
} __attribute__((packed));

struct sensorreadingresp_t
{
    uint8_t value;
    uint8_t operation;
    uint8_t indication[2];
} __attribute__((packed));

int get_bus_for_path(const char* path, char** busname)
{
    return mapper_get_service(bus, path, busname);
}

// Use a lookup table to find the interface name of a specific sensor
// This will be used until an alternative is found.  this is the first
// step for mapping IPMI
int find_openbmc_path(uint8_t num, dbus_interface_t* interface)
{
    int rc;

    const auto& sensor_it = sensors.find(num);
    if (sensor_it == sensors.end())
    {
        // The sensor map does not contain the sensor requested
        return -EINVAL;
    }

    const auto& info = sensor_it->second;

    char* busname = nullptr;
    rc = get_bus_for_path(info.sensorPath.c_str(), &busname);
    if (rc < 0)
    {
        std::fprintf(stderr, "Failed to get %s busname: %s\n",
                     info.sensorPath.c_str(), busname);
        goto final;
    }

    interface->sensortype = info.sensorType;
    strcpy(interface->bus, busname);
    strcpy(interface->path, info.sensorPath.c_str());
    // Take the interface name from the beginning of the DbusInterfaceMap. This
    // works for the Value interface but may not suffice for more complex
    // sensors.
    // tracked https://github.com/openbmc/phosphor-host-ipmid/issues/103
    strcpy(interface->interface,
           info.propertyInterfaces.begin()->first.c_str());
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
int set_sensor_dbus_state_s(uint8_t number, const char* method,
                            const char* value)
{

    dbus_interface_t a;
    int r;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message* m = NULL;

    r = find_openbmc_path(number, &a);

    if (r < 0)
    {
        std::fprintf(stderr, "Failed to find Sensor 0x%02x\n", number);
        return 0;
    }

    r = sd_bus_message_new_method_call(bus, &m, a.bus, a.path, a.interface,
                                       method);
    if (r < 0)
    {
        std::fprintf(stderr, "Failed to create a method call: %s",
                     strerror(-r));
        goto final;
    }

    r = sd_bus_message_append(m, "v", "s", value);
    if (r < 0)
    {
        std::fprintf(stderr, "Failed to create a input parameter: %s",
                     strerror(-r));
        goto final;
    }

    r = sd_bus_call(bus, m, 0, &error, NULL);
    if (r < 0)
    {
        std::fprintf(stderr, "Failed to call the method: %s", strerror(-r));
    }

final:
    sd_bus_error_free(&error);
    m = sd_bus_message_unref(m);

    return 0;
}
int set_sensor_dbus_state_y(uint8_t number, const char* method,
                            const uint8_t value)
{

    dbus_interface_t a;
    int r;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message* m = NULL;

    r = find_openbmc_path(number, &a);

    if (r < 0)
    {
        std::fprintf(stderr, "Failed to find Sensor 0x%02x\n", number);
        return 0;
    }

    r = sd_bus_message_new_method_call(bus, &m, a.bus, a.path, a.interface,
                                       method);
    if (r < 0)
    {
        std::fprintf(stderr, "Failed to create a method call: %s",
                     strerror(-r));
        goto final;
    }

    r = sd_bus_message_append(m, "v", "i", value);
    if (r < 0)
    {
        std::fprintf(stderr, "Failed to create a input parameter: %s",
                     strerror(-r));
        goto final;
    }

    r = sd_bus_call(bus, m, 0, &error, NULL);
    if (r < 0)
    {
        std::fprintf(stderr, "12 Failed to call the method: %s", strerror(-r));
    }

final:
    sd_bus_error_free(&error);
    m = sd_bus_message_unref(m);

    return 0;
}

uint8_t dbus_to_sensor_type(char* p)
{

    sensorTypemap_t* s = g_SensorTypeMap;
    char r = 0;
    while (s->number != 0xFF)
    {
        if (!strcmp(s->dbusname, p))
        {
            r = s->typecode;
            break;
        }
        s++;
    }

    if (s->number == 0xFF)
        printf("Failed to find Sensor Type %s\n", p);

    return r;
}

uint8_t get_type_from_interface(dbus_interface_t dbus_if)
{

    uint8_t type;

    // This is where sensors that do not exist in dbus but do
    // exist in the host code stop.  This should indicate it
    // is not a supported sensor
    if (dbus_if.interface[0] == 0)
    {
        return 0;
    }

    // Fetch type from interface itself.
    if (dbus_if.sensortype != 0)
    {
        type = dbus_if.sensortype;
    }
    else
    {
        // Non InventoryItems
        char* p = strrchr(dbus_if.path, '/');
        type = dbus_to_sensor_type(p + 1);
    }

    return type;
}

// Replaces find_sensor
uint8_t find_type_for_sensor_number(uint8_t num)
{
    int r;
    dbus_interface_t dbus_if;
    r = find_openbmc_path(num, &dbus_if);
    if (r < 0)
    {
        std::fprintf(stderr, "Could not find sensor %d\n", num);
        return 0;
    }
    return get_type_from_interface(dbus_if);
}

ipmi_ret_t ipmi_sen_get_sensor_type(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                    ipmi_request_t request,
                                    ipmi_response_t response,
                                    ipmi_data_len_t data_len,
                                    ipmi_context_t context)
{
    auto reqptr = static_cast<sensor_data_t*>(request);
    ipmi_ret_t rc = IPMI_CC_OK;

    printf("IPMI GET_SENSOR_TYPE [0x%02X]\n", reqptr->sennum);

    // TODO Not sure what the System-event-sensor is suppose to return
    // need to ask Hostboot team
    unsigned char buf[] = {0x00, 0x6F};

    buf[0] = find_type_for_sensor_number(reqptr->sennum);

    // HACK UNTIL Dbus gets updated or we find a better way
    if (buf[0] == 0)
    {
        rc = IPMI_CC_SENSOR_INVALID;
    }

    *data_len = sizeof(buf);
    std::memcpy(response, &buf, *data_len);

    return rc;
}

const std::set<std::string> analogSensorInterfaces = {
    "xyz.openbmc_project.Sensor.Value",
    "xyz.openbmc_project.Control.FanPwm",
};

bool isAnalogSensor(const std::string& interface)
{
    return (analogSensorInterfaces.count(interface));
}

ipmi_ret_t setSensorReading(void* request)
{
    ipmi::sensor::SetSensorReadingReq cmdData =
        *(static_cast<ipmi::sensor::SetSensorReadingReq*>(request));

    // Check if the Sensor Number is present
    const auto iter = sensors.find(cmdData.number);
    if (iter == sensors.end())
    {
        return IPMI_CC_SENSOR_INVALID;
    }

    try
    {
        if (ipmi::sensor::Mutability::Write !=
            (iter->second.mutability & ipmi::sensor::Mutability::Write))
        {
            log<level::ERR>("Sensor Set operation is not allowed",
                            entry("SENSOR_NUM=%d", cmdData.number));
            return IPMI_CC_ILLEGAL_COMMAND;
        }
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
    auto reqptr = static_cast<sensor_data_t*>(request);

    log<level::DEBUG>("IPMI SET_SENSOR",
                      entry("SENSOR_NUM=0x%02x", reqptr->sennum));

    /*
     * This would support the Set Sensor Reading command for the presence
     * and functional state of Processor, Core & DIMM. For the remaining
     * sensors the existing support is invoked.
     */
    auto ipmiRC = setSensorReading(request);

    if (ipmiRC == IPMI_CC_SENSOR_INVALID)
    {
        updateSensorRecordFromSSRAESC(reqptr);
        ipmiRC = IPMI_CC_OK;
    }

    *data_len = 0;
    return ipmiRC;
}

ipmi_ret_t ipmi_sen_get_sensor_reading(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                       ipmi_request_t request,
                                       ipmi_response_t response,
                                       ipmi_data_len_t data_len,
                                       ipmi_context_t context)
{
    auto reqptr = static_cast<sensor_data_t*>(request);
    auto resp = static_cast<sensorreadingresp_t*>(response);
    ipmi::sensor::GetSensorResponse getResponse{};
    static constexpr auto scanningEnabledBit = 6;

    const auto iter = sensors.find(reqptr->sennum);
    if (iter == sensors.end())
    {
        return IPMI_CC_SENSOR_INVALID;
    }
    if (ipmi::sensor::Mutability::Read !=
        (iter->second.mutability & ipmi::sensor::Mutability::Read))
    {
        return IPMI_CC_ILLEGAL_COMMAND;
    }

    try
    {
        getResponse = iter->second.getFunc(iter->second);
        *data_len = getResponse.size();
        std::memcpy(resp, getResponse.data(), *data_len);
        resp->operation = 1 << scanningEnabledBit;
        return IPMI_CC_OK;
    }
    catch (const std::exception& e)
    {
        *data_len = getResponse.size();
        std::memcpy(resp, getResponse.data(), *data_len);
        return IPMI_CC_OK;
    }
}

void getSensorThresholds(uint8_t sensorNum,
                         get_sdr::GetSensorThresholdsResponse* response)
{
    constexpr auto warningThreshIntf =
        "xyz.openbmc_project.Sensor.Threshold.Warning";
    constexpr auto criticalThreshIntf =
        "xyz.openbmc_project.Sensor.Threshold.Critical";

    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};

    const auto iter = sensors.find(sensorNum);
    const auto info = iter->second;

    auto service = ipmi::getService(bus, info.sensorInterface, info.sensorPath);

    auto warnThresholds = ipmi::getAllDbusProperties(
        bus, service, info.sensorPath, warningThreshIntf);

    double warnLow = std::visit(ipmi::VariantToDoubleVisitor(),
                                warnThresholds["WarningLow"]);
    double warnHigh = std::visit(ipmi::VariantToDoubleVisitor(),
                                 warnThresholds["WarningHigh"]);

    if (warnLow != 0)
    {
        warnLow *= std::pow(10, info.scale - info.exponentR);
        response->lowerNonCritical = static_cast<uint8_t>(
            (warnLow - info.scaledOffset) / info.coefficientM);
        response->validMask |= static_cast<uint8_t>(
            ipmi::sensor::ThresholdMask::NON_CRITICAL_LOW_MASK);
    }

    if (warnHigh != 0)
    {
        warnHigh *= std::pow(10, info.scale - info.exponentR);
        response->upperNonCritical = static_cast<uint8_t>(
            (warnHigh - info.scaledOffset) / info.coefficientM);
        response->validMask |= static_cast<uint8_t>(
            ipmi::sensor::ThresholdMask::NON_CRITICAL_HIGH_MASK);
    }

    auto critThresholds = ipmi::getAllDbusProperties(
        bus, service, info.sensorPath, criticalThreshIntf);
    double critLow = std::visit(ipmi::VariantToDoubleVisitor(),
                                critThresholds["CriticalLow"]);
    double critHigh = std::visit(ipmi::VariantToDoubleVisitor(),
                                 critThresholds["CriticalHigh"]);

    if (critLow != 0)
    {
        critLow *= std::pow(10, info.scale - info.exponentR);
        response->lowerCritical = static_cast<uint8_t>(
            (critLow - info.scaledOffset) / info.coefficientM);
        response->validMask |= static_cast<uint8_t>(
            ipmi::sensor::ThresholdMask::CRITICAL_LOW_MASK);
    }

    if (critHigh != 0)
    {
        critHigh *= std::pow(10, info.scale - info.exponentR);
        response->upperCritical = static_cast<uint8_t>(
            (critHigh - info.scaledOffset) / info.coefficientM);
        response->validMask |= static_cast<uint8_t>(
            ipmi::sensor::ThresholdMask::CRITICAL_HIGH_MASK);
    }
}

ipmi_ret_t ipmi_sen_get_sensor_thresholds(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                          ipmi_request_t request,
                                          ipmi_response_t response,
                                          ipmi_data_len_t data_len,
                                          ipmi_context_t context)
{
    constexpr auto valueInterface = "xyz.openbmc_project.Sensor.Value";

    if (*data_len != sizeof(uint8_t))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    auto sensorNum = *(reinterpret_cast<const uint8_t*>(request));
    *data_len = 0;

    const auto iter = sensors.find(sensorNum);
    if (iter == sensors.end())
    {
        return IPMI_CC_SENSOR_INVALID;
    }

    const auto info = iter->second;

    // Proceed only if the sensor value interface is implemented.
    if (info.propertyInterfaces.find(valueInterface) ==
        info.propertyInterfaces.end())
    {
        // return with valid mask as 0
        return IPMI_CC_OK;
    }

    auto responseData =
        reinterpret_cast<get_sdr::GetSensorThresholdsResponse*>(response);

    try
    {
        getSensorThresholds(sensorNum, responseData);
    }
    catch (std::exception& e)
    {
        // Mask if the property is not present
        responseData->validMask = 0;
    }

    *data_len = sizeof(get_sdr::GetSensorThresholdsResponse);
    return IPMI_CC_OK;
}

ipmi_ret_t ipmi_sen_wildcard(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_INVALID;

    printf("IPMI S/E Wildcard Netfn:[0x%X], Cmd:[0x%X]\n", netfn, cmd);
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
        resp->count = sensors.size() + frus.size() + entities.size();
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

void setUnitFieldsForObject(const ipmi::sensor::Info* info,
                            get_sdr::SensorDataFullRecordBody* body)
{
    namespace server = sdbusplus::xyz::openbmc_project::Sensor::server;
    try
    {
        auto unit = server::Value::convertUnitFromString(info->unit);
        // Unit strings defined in
        // phosphor-dbus-interfaces/xyz/openbmc_project/Sensor/Value.interface.yaml
        switch (unit)
        {
            case server::Value::Unit::DegreesC:
                body->sensor_units_2_base = get_sdr::SENSOR_UNIT_DEGREES_C;
                break;
            case server::Value::Unit::RPMS:
                body->sensor_units_2_base = get_sdr::SENSOR_UNIT_RPM;
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
            case server::Value::Unit::Watts:
                body->sensor_units_2_base = get_sdr::SENSOR_UNIT_WATTS;
                break;
            default:
                // Cannot be hit.
                std::fprintf(stderr, "Unknown value unit type: = %s\n",
                             info->unit.c_str());
        }
    }
    catch (const sdbusplus::exception::InvalidEnumString& e)
    {
        log<level::WARNING>("Warning: no unit provided for sensor!");
    }
}

ipmi_ret_t populate_record_from_dbus(get_sdr::SensorDataFullRecordBody* body,
                                     const ipmi::sensor::Info* info,
                                     ipmi_data_len_t data_len)
{
    /* Functional sensor case */
    if (isAnalogSensor(info->propertyInterfaces.begin()->first))
    {

        body->sensor_units_1 = 0; // unsigned, no rate, no modifier, not a %

        /* Unit info */
        setUnitFieldsForObject(info, body);

        get_sdr::body::set_b(info->coefficientB, body);
        get_sdr::body::set_m(info->coefficientM, body);
        get_sdr::body::set_b_exp(info->exponentB, body);
        get_sdr::body::set_r_exp(info->exponentR, body);

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

ipmi_ret_t ipmi_fru_get_sdr(ipmi_request_t request, ipmi_response_t response,
                            ipmi_data_len_t data_len)
{
    auto req = reinterpret_cast<get_sdr::GetSdrReq*>(request);
    auto resp = reinterpret_cast<get_sdr::GetSdrResp*>(response);
    get_sdr::SensorDataFruRecord record{};
    auto dataLength = 0;

    auto fru = frus.begin();
    uint8_t fruID{};
    auto recordID = get_sdr::request::get_record_id(req);

    fruID = recordID - FRU_RECORD_ID_START;
    fru = frus.find(fruID);
    if (fru == frus.end())
    {
        return IPMI_CC_SENSOR_INVALID;
    }

    /* Header */
    get_sdr::header::set_record_id(recordID, &(record.header));
    record.header.sdr_version = SDR_VERSION; // Based on IPMI Spec v2.0 rev 1.1
    record.header.record_type = get_sdr::SENSOR_DATA_FRU_RECORD;
    record.header.record_length = sizeof(record.key) + sizeof(record.body);

    /* Key */
    record.key.fruID = fruID;
    record.key.accessLun |= IPMI_LOGICAL_FRU;
    record.key.deviceAddress = BMCSlaveAddress;

    /* Body */
    record.body.entityID = fru->second[0].entityID;
    record.body.entityInstance = fru->second[0].entityInstance;
    record.body.deviceType = fruInventoryDevice;
    record.body.deviceTypeModifier = IPMIFruInventory;

    /* Device ID string */
    auto deviceID =
        fru->second[0].path.substr(fru->second[0].path.find_last_of('/') + 1,
                                   fru->second[0].path.length());

    if (deviceID.length() > get_sdr::FRU_RECORD_DEVICE_ID_MAX_LENGTH)
    {
        get_sdr::body::set_device_id_strlen(
            get_sdr::FRU_RECORD_DEVICE_ID_MAX_LENGTH, &(record.body));
    }
    else
    {
        get_sdr::body::set_device_id_strlen(deviceID.length(), &(record.body));
    }

    strncpy(record.body.deviceID, deviceID.c_str(),
            get_sdr::body::get_device_id_strlen(&(record.body)));

    if (++fru == frus.end())
    {
        // we have reached till end of fru, so assign the next record id to
        // 512(Max fru ID = 511) + Entity Record ID(may start with 0).
        auto next_record_id =
            (entities.size()) ? entities.begin()->first + ENTITY_RECORD_ID_START
                              : END_OF_RECORD;
        get_sdr::response::set_next_record_id(next_record_id, resp);
    }
    else
    {
        get_sdr::response::set_next_record_id(
            (FRU_RECORD_ID_START + fru->first), resp);
    }

    // Check for invalid offset size
    if (req->offset > sizeof(record))
    {
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    dataLength = std::min(static_cast<size_t>(req->bytes_to_read),
                          sizeof(record) - req->offset);

    std::memcpy(resp->record_data,
                reinterpret_cast<uint8_t*>(&record) + req->offset, dataLength);

    *data_len = dataLength;
    *data_len += 2; // additional 2 bytes for next record ID

    return IPMI_CC_OK;
}

ipmi_ret_t ipmi_entity_get_sdr(ipmi_request_t request, ipmi_response_t response,
                               ipmi_data_len_t data_len)
{
    auto req = reinterpret_cast<get_sdr::GetSdrReq*>(request);
    auto resp = reinterpret_cast<get_sdr::GetSdrResp*>(response);
    get_sdr::SensorDataEntityRecord record{};
    auto dataLength = 0;

    auto entity = entities.begin();
    uint8_t entityRecordID;
    auto recordID = get_sdr::request::get_record_id(req);

    entityRecordID = recordID - ENTITY_RECORD_ID_START;
    entity = entities.find(entityRecordID);
    if (entity == entities.end())
    {
        return IPMI_CC_SENSOR_INVALID;
    }

    /* Header */
    get_sdr::header::set_record_id(recordID, &(record.header));
    record.header.sdr_version = SDR_VERSION; // Based on IPMI Spec v2.0 rev 1.1
    record.header.record_type = get_sdr::SENSOR_DATA_ENTITY_RECORD;
    record.header.record_length = sizeof(record.key) + sizeof(record.body);

    /* Key */
    record.key.containerEntityId = entity->second.containerEntityId;
    record.key.containerEntityInstance = entity->second.containerEntityInstance;
    get_sdr::key::set_flags(entity->second.isList, entity->second.isLinked,
                            &(record.key));
    record.key.entityId1 = entity->second.containedEntities[0].first;
    record.key.entityInstance1 = entity->second.containedEntities[0].second;

    /* Body */
    record.body.entityId2 = entity->second.containedEntities[1].first;
    record.body.entityInstance2 = entity->second.containedEntities[1].second;
    record.body.entityId3 = entity->second.containedEntities[2].first;
    record.body.entityInstance3 = entity->second.containedEntities[2].second;
    record.body.entityId4 = entity->second.containedEntities[3].first;
    record.body.entityInstance4 = entity->second.containedEntities[3].second;

    if (++entity == entities.end())
    {
        get_sdr::response::set_next_record_id(END_OF_RECORD,
                                              resp); // last record
    }
    else
    {
        get_sdr::response::set_next_record_id(
            (ENTITY_RECORD_ID_START + entity->first), resp);
    }

    // Check for invalid offset size
    if (req->offset > sizeof(record))
    {
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    dataLength = std::min(static_cast<size_t>(req->bytes_to_read),
                          sizeof(record) - req->offset);

    std::memcpy(resp->record_data,
                reinterpret_cast<uint8_t*>(&record) + req->offset, dataLength);

    *data_len = dataLength;
    *data_len += 2; // additional 2 bytes for next record ID

    return IPMI_CC_OK;
}

ipmi_ret_t ipmi_sen_get_sdr(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                            ipmi_request_t request, ipmi_response_t response,
                            ipmi_data_len_t data_len, ipmi_context_t context)
{
    ipmi_ret_t ret = IPMI_CC_OK;
    get_sdr::GetSdrReq* req = (get_sdr::GetSdrReq*)request;
    get_sdr::GetSdrResp* resp = (get_sdr::GetSdrResp*)response;
    get_sdr::SensorDataFullRecord record = {0};
    if (req != NULL)
    {
        // Note: we use an iterator so we can provide the next ID at the end of
        // the call.
        auto sensor = sensors.begin();
        auto recordID = get_sdr::request::get_record_id(req);

        // At the beginning of a scan, the host side will send us id=0.
        if (recordID != 0)
        {
            // recordID 0 to 255 means it is a FULL record.
            // recordID 256 to 511 means it is a FRU record.
            // recordID greater then 511 means it is a Entity Association
            // record. Currently we are supporting three record types: FULL
            // record, FRU record and Enttiy Association record.
            if (recordID >= ENTITY_RECORD_ID_START)
            {
                return ipmi_entity_get_sdr(request, response, data_len);
            }
            else if (recordID >= FRU_RECORD_ID_START &&
                     recordID < ENTITY_RECORD_ID_START)
            {
                return ipmi_fru_get_sdr(request, response, data_len);
            }
            else
            {
                sensor = sensors.find(recordID);
                if (sensor == sensors.end())
                {
                    return IPMI_CC_SENSOR_INVALID;
                }
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
        if (ipmi::sensor::Mutability::Write ==
            (sensor->second.mutability & ipmi::sensor::Mutability::Write))
        {
            get_sdr::body::init_settable_state(true, &(record.body));
        }

        // Set the type-specific details given the DBus interface
        ret = populate_record_from_dbus(&(record.body), &(sensor->second),
                                        data_len);

        if (++sensor == sensors.end())
        {
            // we have reached till end of sensor, so assign the next record id
            // to 256(Max Sensor ID = 255) + FRU ID(may start with 0).
            auto next_record_id =
                (frus.size()) ? frus.begin()->first + FRU_RECORD_ID_START
                              : END_OF_RECORD;

            get_sdr::response::set_next_record_id(next_record_id, resp);
        }
        else
        {
            get_sdr::response::set_next_record_id(sensor->first, resp);
        }

        if (req->offset > sizeof(record))
        {
            return IPMI_CC_PARM_OUT_OF_RANGE;
        }

        // data_len will ultimately be the size of the record, plus
        // the size of the next record ID:
        *data_len = std::min(static_cast<size_t>(req->bytes_to_read),
                             sizeof(record) - req->offset);

        std::memcpy(resp->record_data,
                    reinterpret_cast<uint8_t*>(&record) + req->offset,
                    *data_len);

        // data_len should include the LSB and MSB:
        *data_len +=
            sizeof(resp->next_record_id_lsb) + sizeof(resp->next_record_id_msb);
    }

    return ret;
}

static bool isFromSystemChannel()
{
    // TODO we could not figure out where the request is from based on IPMI
    // command handler parameters. because of it, we can not differentiate
    // request from SMS/SMM or IPMB channel
    return true;
}

ipmi_ret_t ipmicmdPlatformEvent(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request,
                                ipmi_response_t response,
                                ipmi_data_len_t dataLen, ipmi_context_t context)
{
    uint16_t generatorID;
    size_t count;
    bool assert = true;
    std::string sensorPath;
    size_t paraLen = *dataLen;
    PlatformEventRequest* req;
    *dataLen = 0;

    if ((paraLen < selSystemEventSizeWith1Bytes) ||
        (paraLen > selSystemEventSizeWith3Bytes))
    {
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    if (isFromSystemChannel())
    { // first byte for SYSTEM Interface is Generator ID
        // +1 to get common struct
        req = reinterpret_cast<PlatformEventRequest*>((uint8_t*)request + 1);
        // Capture the generator ID
        generatorID = *reinterpret_cast<uint8_t*>(request);
        // Platform Event usually comes from other firmware, like BIOS.
        // Unlike BMC sensor, it does not have BMC DBUS sensor path.
        sensorPath = "System";
    }
    else
    {
        req = reinterpret_cast<PlatformEventRequest*>(request);
        // TODO GenratorID for IPMB is combination of RqSA and RqLUN
        generatorID = 0xff;
        sensorPath = "IPMB";
    }
    // Content of event data field depends on sensor class.
    // When data0 bit[5:4] is non-zero, valid data counts is 3.
    // When data0 bit[7:6] is non-zero, valid data counts is 2.
    if (((req->data[0] & byte3EnableMask) != 0 &&
         paraLen < selSystemEventSizeWith3Bytes) ||
        ((req->data[0] & byte2EnableMask) != 0 &&
         paraLen < selSystemEventSizeWith2Bytes))
    {
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    // Count bytes of Event Data
    if ((req->data[0] & byte3EnableMask) != 0)
    {
        count = 3;
    }
    else if ((req->data[0] & byte2EnableMask) != 0)
    {
        count = 2;
    }
    else
    {
        count = 1;
    }
    assert = req->eventDirectionType & directionMask ? false : true;
    std::vector<uint8_t> eventData(req->data, req->data + count);

    sdbusplus::bus::bus dbus(bus);
    std::string service =
        ipmi::getService(dbus, ipmiSELAddInterface, ipmiSELPath);
    sdbusplus::message::message writeSEL = dbus.new_method_call(
        service.c_str(), ipmiSELPath, ipmiSELAddInterface, "IpmiSelAdd");
    writeSEL.append(ipmiSELAddMessage, sensorPath, eventData, assert,
                    generatorID);
    try
    {
        dbus.call(writeSEL);
    }
    catch (sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    return IPMI_CC_OK;
}

void register_netfn_sen_functions()
{
    // <Wildcard Command>
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_WILDCARD, nullptr,
                           ipmi_sen_wildcard, PRIVILEGE_USER);

    // <Platform Event Message>
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_PLATFORM_EVENT, nullptr,
                           ipmicmdPlatformEvent, PRIVILEGE_OPERATOR);
    // <Get Sensor Type>
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_GET_SENSOR_TYPE, nullptr,
                           ipmi_sen_get_sensor_type, PRIVILEGE_USER);

    // <Set Sensor Reading and Event Status>
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_SET_SENSOR, nullptr,
                           ipmi_sen_set_sensor, PRIVILEGE_OPERATOR);

    // <Get Sensor Reading>
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_GET_SENSOR_READING, nullptr,
                           ipmi_sen_get_sensor_reading, PRIVILEGE_USER);

    // <Reserve Device SDR Repository>
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_RESERVE_DEVICE_SDR_REPO,
                           nullptr, ipmi_sen_reserve_sdr, PRIVILEGE_USER);

    // <Get Device SDR Info>
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_GET_DEVICE_SDR_INFO, nullptr,
                           ipmi_sen_get_sdr_info, PRIVILEGE_USER);

    // <Get Device SDR>
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_GET_DEVICE_SDR, nullptr,
                           ipmi_sen_get_sdr, PRIVILEGE_USER);

    // <Get Sensor Thresholds>
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_GET_SENSOR_THRESHOLDS,
                           nullptr, ipmi_sen_get_sensor_thresholds,
                           PRIVILEGE_USER);

    return;
}
