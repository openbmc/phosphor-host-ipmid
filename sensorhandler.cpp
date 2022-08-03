#include "config.h"

#include "sensorhandler.hpp"

#include "entity_map_json.hpp"
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
#include <phosphor-logging/lg2.hpp>
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

namespace ipmi
{
namespace sensor
{
#ifdef FEATURE_SENSORS_OVERRIDE
extern IdInfoMap sensors;
#else
extern const IdInfoMap sensors;
#endif
} // namespace sensor
} // namespace ipmi

extern const FruMap frus;

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

using SDRCacheMap = std::unordered_map<uint8_t, get_sdr::SensorDataFullRecord>;
SDRCacheMap sdrCacheMap __attribute__((init_priority(101)));

using SensorThresholdMap =
    std::unordered_map<uint8_t, get_sdr::GetSensorThresholdsResponse>;
SensorThresholdMap sensorThresholdMap __attribute__((init_priority(101)));

#ifdef FEATURE_SENSORS_CACHE
std::map<uint8_t, std::unique_ptr<sdbusplus::bus::match_t>> sensorAddedMatches
    __attribute__((init_priority(101)));
std::map<uint8_t, std::unique_ptr<sdbusplus::bus::match_t>> sensorUpdatedMatches
    __attribute__((init_priority(101)));
std::map<uint8_t, std::unique_ptr<sdbusplus::bus::match_t>> sensorRemovedMatches
    __attribute__((init_priority(101)));
std::unique_ptr<sdbusplus::bus::match_t> sensorsOwnerMatch
    __attribute__((init_priority(101)));

ipmi::sensor::SensorCacheMap sensorCacheMap __attribute__((init_priority(101)));

// It is needed to know which objects belong to which service, so that when a
// service exits without interfacesRemoved signal, we could invaildate the cache
// that is related to the service. It uses below two variables:
// - idToServiceMap records which sensors are known to have a related service;
// - serviceToIdMap maps a service to the sensors.
using sensorIdToServiceMap = std::unordered_map<uint8_t, std::string>;
sensorIdToServiceMap idToServiceMap __attribute__((init_priority(101)));

using sensorServiceToIdMap = std::unordered_map<std::string, std::set<uint8_t>>;
sensorServiceToIdMap serviceToIdMap __attribute__((init_priority(101)));

static void fillSensorIdServiceMap(const std::string&,
                                   const std::string& /*intf*/, uint8_t id,
                                   const std::string& service)
{
    if (idToServiceMap.find(id) != idToServiceMap.end())
    {
        return;
    }
    idToServiceMap[id] = service;
    serviceToIdMap[service].insert(id);
}

static void fillSensorIdServiceMap(const std::string& obj,
                                   const std::string& intf, uint8_t id)
{
    if (idToServiceMap.find(id) != idToServiceMap.end())
    {
        return;
    }
    try
    {
        sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};
        auto service = ipmi::getService(bus, intf, obj);
        idToServiceMap[id] = service;
        serviceToIdMap[service].insert(id);
    }
    catch (...)
    {
        // Ignore
    }
}

void initOneSensorMatches(ipmi::sensor::IdInfoMap::const_iterator it)
{
    using namespace sdbusplus::bus::match::rules;
    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};

    const auto& s = *it;

    sensorAddedMatches.emplace(
        s.first,
        std::make_unique<sdbusplus::bus::match_t>(
            bus, interfacesAdded() + argNpath(0, s.second.sensorPath),
            [id = s.first, obj = s.second.sensorPath,
             intf = s.second.propertyInterfaces.begin()->first](auto& /*msg*/) {
                fillSensorIdServiceMap(obj, intf, id);
            }));
    sensorRemovedMatches.emplace(
        s.first,
        std::make_unique<sdbusplus::bus::match_t>(
            bus, interfacesRemoved() + argNpath(0, s.second.sensorPath),
            [id = s.first](auto& /*msg*/) {
                // Ideally this should work.
                // But when a service is terminated or crashed, it does not
                // emit interfacesRemoved signal. In that case it's handled
                // by sensorsOwnerMatch
                sensorCacheMap[id].reset();
            }));
    sensorUpdatedMatches.emplace(
        s.first, std::make_unique<sdbusplus::bus::match_t>(
                     bus,
                     type::signal() + path(s.second.sensorPath) +
                         member("PropertiesChanged"s) +
                         interface("org.freedesktop.DBus.Properties"s),
                     [&s](auto& msg) {
                         fillSensorIdServiceMap(
                             s.second.sensorPath,
                             s.second.propertyInterfaces.begin()->first,
                             s.first);
                         try
                         {
                             // This is signal callback
                             std::string interfaceName;
                             msg.read(interfaceName);
                             ipmi::PropertyMap props;
                             msg.read(props);
                             s.second.getFunc(s.first, s.second, props);
                         }
                         catch (const std::exception& e)
                         {
                             sensorCacheMap[s.first].reset();
                         }
                     }));
}

void clearOneSensorMatches(const uint8_t id)
{
    sensorAddedMatches.erase(id);
    idToServiceMap.erase(id);
    sensorRemovedMatches.erase(id);
    sensorUpdatedMatches.erase(id);
}

void reInitOneSensorMatches(const uint8_t id)
{
    auto it = ipmi::sensor::sensors.find(id);
    if (it == ipmi::sensor::sensors.end())
    {
        return;
    }
    clearOneSensorMatches(id);
    initOneSensorMatches(it);
}

void initSensorMatches()
{
    using namespace sdbusplus::bus::match::rules;
    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};

    for (auto it = ipmi::sensor::sensors.begin();
         it != ipmi::sensor::sensors.end(); ++it)
    {
        initOneSensorMatches(it);
    }

    sensorsOwnerMatch = std::make_unique<sdbusplus::bus::match_t>(
        bus, nameOwnerChanged(), [](auto& msg) {
            std::string name;
            std::string oldOwner;
            std::string newOwner;
            msg.read(name, oldOwner, newOwner);

            if (!name.empty() && newOwner.empty())
            {
                // The service exits
                const auto it = serviceToIdMap.find(name);
                if (it == serviceToIdMap.end())
                {
                    return;
                }
                for (const auto& id : it->second)
                {
                    // Invalidate cache
                    sensorCacheMap[id].reset();
                }
            }
        });
}
#endif

#ifdef FEATURE_SENSORS_OVERRIDE

/**
 * @key: uint8_t: sensor id, std::string: sensor override path
 * @value: std::unique_ptr<ipmi::SensorOverride>
 */
using SensorOverrideMatchMap =
    std::map<std::pair<uint8_t, std::string>,
             std::unique_ptr<sdbusplus::bus::match_t>>;

SensorOverrideMatchMap sensorOverrideMatches
    __attribute__((init_priority(101)));

/**
 * @brief Get the override from the dbus, if it exists, override the sensor
 * path
 *
 */
void initSensorOverride()
{
    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};

    for (auto& sensor : ipmi::sensor::sensors)
    {
        // If the sensor has no override, continue
        if (sensor.second.overridePaths.empty())
        {
            continue;
        }

        lg2::debug("Sensor {ID} : {SENSOR} have override paths", "ID",
                   sensor.first, "SENSOR", sensor.second.sensorPath);

        for (const auto& path : sensor.second.overridePaths)
        {
            try
            {
                // if override is found, the sensor path is used
                // as the override path
                ipmi::getService(bus, sensor.second.sensorInterface, path);
                lg2::debug("Sensor {ID} : {SENSOR} override to path {PATH}",
                           "ID", sensor.first, "SENSOR",
                           sensor.second.sensorPath, "PATH", path);
                sensor.second.sensorPath = path;
                break;
            }
            catch (const std::exception& e)
            {
                lg2::info("No override found for sensor {PATH}, {INFO}", "PATH",
                          sensor.first, "INFO", e.what());
            }
        }
    }
}

void initSensorOverrideMatches()
{
    using namespace sdbusplus::bus::match::rules;
    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};

    for (auto& [id, info] : ipmi::sensor::sensors)
    {
        // for all sensors with override paths, create a match for the override
        for (const auto& path : info.overridePaths)
        {
            sensorOverrideMatches[std::make_pair(id, path)] = std::make_unique<
                sdbusplus::bus::match_t>(
                bus, interfacesAdded() + argNpath(0, path),
                [id, path, &info](auto& msg) {
                    using InterfaceType = std::map<
                        std::string,
                        std::map<std::string, std::variant<std::string>>>;
                    sdbusplus::message::object_path objPath;
                    InterfaceType interfaces;
                    try
                    {
                        msg.read(objPath, interfaces);
                    }
                    catch (const std::exception& e)
                    {
                        lg2::error("Failed to read message: {INFO}", "INFO",
                                   e.what());
                        return;
                    }

                    lg2::debug("Sensor {ID} : {SENSOR} override path {PATH} "
                               "interfaces added",
                               "ID", id, "SENSOR", info.sensorPath, "PATH",
                               static_cast<std::string>(objPath));

                    if (interfaces.find(info.sensorInterface) ==
                        interfaces.end())
                    {
                        lg2::debug("Sensor {ID} : No interface {INTERFACE} "
                                   "found",
                                   "ID", id, "INTERFACE", info.sensorInterface);
                        return;
                    }

                    lg2::debug(
                        "Sensor {ID} : old {SENSOR} override path to {PATH}",
                        "ID", id, "SENSOR", info.sensorPath, "PATH", path);

                    info.sensorPath = path;

                    // clear sdr and threshold cache, will be reloaded on next
                    sdrCacheMap.erase(id);
                    sensorThresholdMap.erase(id);
#ifdef FEATURE_SENSORS_CACHE
                    reInitOneSensorMatches(id);
#endif
                });
        }
    }
}
#endif

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

    const auto& sensor_it = ipmi::sensor::sensors.find(num);
    if (sensor_it == ipmi::sensor::sensors.end())
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

/**
 *  @brief implements the get sensor type command.
 *  @param - sensorNumber
 *
 *  @return IPMI completion code plus response data on success.
 *   - sensorType
 *   - eventType
 **/

ipmi::RspType<uint8_t, // sensorType
              uint8_t  // eventType
              >
    ipmiGetSensorType(uint8_t sensorNumber)
{
    uint8_t sensorType = find_type_for_sensor_number(sensorNumber);

    if (sensorType == 0)
    {
        return ipmi::responseSensorInvalid();
    }

    constexpr uint8_t eventType = 0x6F;
    return ipmi::responseSuccess(sensorType, eventType);
}

const std::set<std::string> analogSensorInterfaces = {
    "xyz.openbmc_project.Sensor.Value",
    "xyz.openbmc_project.Control.FanPwm",
};

bool isAnalogSensor(const std::string& interface)
{
    return (analogSensorInterfaces.count(interface));
}

/**
@brief This command is used to set sensorReading.

@param
    -  sensorNumber
    -  operation
    -  reading
    -  assertOffset0_7
    -  assertOffset8_14
    -  deassertOffset0_7
    -  deassertOffset8_14
    -  eventData1
    -  eventData2
    -  eventData3

@return completion code on success.
**/

ipmi::RspType<> ipmiSetSensorReading(uint8_t sensorNumber, uint8_t operation,
                                     uint8_t reading, uint8_t assertOffset0_7,
                                     uint8_t assertOffset8_14,
                                     uint8_t deassertOffset0_7,
                                     uint8_t deassertOffset8_14,
                                     uint8_t eventData1, uint8_t eventData2,
                                     uint8_t eventData3)
{
    log<level::DEBUG>("IPMI SET_SENSOR",
                      entry("SENSOR_NUM=0x%02x", sensorNumber));

    if (sensorNumber == 0xFF)
    {
        return ipmi::responseInvalidFieldRequest();
    }
    ipmi::sensor::SetSensorReadingReq cmdData;

    cmdData.number = sensorNumber;
    cmdData.operation = operation;
    cmdData.reading = reading;
    cmdData.assertOffset0_7 = assertOffset0_7;
    cmdData.assertOffset8_14 = assertOffset8_14;
    cmdData.deassertOffset0_7 = deassertOffset0_7;
    cmdData.deassertOffset8_14 = deassertOffset8_14;
    cmdData.eventData1 = eventData1;
    cmdData.eventData2 = eventData2;
    cmdData.eventData3 = eventData3;

    // Check if the Sensor Number is present
    const auto iter = ipmi::sensor::sensors.find(sensorNumber);
    if (iter == ipmi::sensor::sensors.end())
    {
        updateSensorRecordFromSSRAESC(&sensorNumber);
        return ipmi::responseSuccess();
    }

    try
    {
        if (ipmi::sensor::Mutability::Write !=
            (iter->second.mutability & ipmi::sensor::Mutability::Write))
        {
            log<level::ERR>("Sensor Set operation is not allowed",
                            entry("SENSOR_NUM=%d", sensorNumber));
            return ipmi::responseIllegalCommand();
        }
        auto ipmiRC = iter->second.updateFunc(cmdData, iter->second);
        return ipmi::response(ipmiRC);
    }
    catch (const InternalFailure& e)
    {
        log<level::ERR>("Set sensor failed",
                        entry("SENSOR_NUM=%d", sensorNumber));
        commit<InternalFailure>();
        return ipmi::responseUnspecifiedError();
    }
    catch (const std::runtime_error& e)
    {
        log<level::ERR>(e.what());
        return ipmi::responseUnspecifiedError();
    }
}

/** @brief implements the get sensor reading command
 *  @param sensorNum - sensor number
 *
 *  @returns IPMI completion code plus response data
 *   - senReading           - sensor reading
 *   - reserved
 *   - readState            - sensor reading state enabled
 *   - senScanState         - sensor scan state disabled
 *   - allEventMessageState - all Event message state disabled
 *   - assertionStatesLsb   - threshold levels states
 *   - assertionStatesMsb   - discrete reading sensor states
 */
ipmi::RspType<uint8_t, // sensor reading

              uint5_t, // reserved
              bool,    // reading state
              bool,    // 0 = sensor scanning state disabled
              bool,    // 0 = all event messages disabled

              uint8_t, // threshold levels states
              uint8_t  // discrete reading sensor states
              >
    ipmiSensorGetSensorReading([[maybe_unused]] ipmi::Context::ptr& ctx,
                               uint8_t sensorNum)
{
    if (sensorNum == 0xFF)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    const auto iter = ipmi::sensor::sensors.find(sensorNum);
    if (iter == ipmi::sensor::sensors.end())
    {
        return ipmi::responseSensorInvalid();
    }
    if (ipmi::sensor::Mutability::Read !=
        (iter->second.mutability & ipmi::sensor::Mutability::Read))
    {
        return ipmi::responseIllegalCommand();
    }

    try
    {
#ifdef FEATURE_SENSORS_CACHE
        auto& sensorData = sensorCacheMap[sensorNum];
        if (!sensorData.has_value())
        {
            // No cached value, try read it
            std::string service;
            boost::system::error_code ec;
            const auto& sensorInfo = iter->second;
            ec = ipmi::getService(ctx, sensorInfo.sensorInterface,
                                  sensorInfo.sensorPath, service);
            if (ec)
            {
                return ipmi::responseUnspecifiedError();
            }
            fillSensorIdServiceMap(sensorInfo.sensorPath,
                                   sensorInfo.propertyInterfaces.begin()->first,
                                   iter->first, service);

            ipmi::PropertyMap props;
            ec = ipmi::getAllDbusProperties(
                ctx, service, sensorInfo.sensorPath,
                sensorInfo.propertyInterfaces.begin()->first, props);
            if (ec)
            {
                fprintf(stderr, "Failed to get sensor %s, %d: %s\n",
                        sensorInfo.sensorPath.c_str(), ec.value(),
                        ec.message().c_str());
                // Intitilizing with default values
                constexpr uint8_t senReading = 0;
                constexpr uint5_t reserved{0};
                constexpr bool readState = true;
                constexpr bool senScanState = false;
                constexpr bool allEventMessageState = false;
                constexpr uint8_t assertionStatesLsb = 0;
                constexpr uint8_t assertionStatesMsb = 0;

                return ipmi::responseSuccess(senReading, reserved, readState,
                                             senScanState, allEventMessageState,
                                             assertionStatesLsb,
                                             assertionStatesMsb);
            }
            sensorInfo.getFunc(sensorNum, sensorInfo, props);
        }
        return ipmi::responseSuccess(
            sensorData->response.reading, uint5_t(0),
            sensorData->response.readingOrStateUnavailable,
            sensorData->response.scanningEnabled,
            sensorData->response.allEventMessagesEnabled,
            sensorData->response.thresholdLevelsStates,
            sensorData->response.discreteReadingSensorStates);

#else
        ipmi::sensor::GetSensorResponse getResponse =
            iter->second.getFunc(iter->second);

        return ipmi::responseSuccess(getResponse.reading, uint5_t(0),
                                     getResponse.readingOrStateUnavailable,
                                     getResponse.scanningEnabled,
                                     getResponse.allEventMessagesEnabled,
                                     getResponse.thresholdLevelsStates,
                                     getResponse.discreteReadingSensorStates);
#endif
    }
#ifdef UPDATE_FUNCTIONAL_ON_FAIL
    catch (const SensorFunctionalError& e)
    {
        return ipmi::responseResponseError();
    }
#endif
    catch (const std::exception& e)
    {
        // Intitilizing with default values
        constexpr uint8_t senReading = 0;
        constexpr uint5_t reserved{0};
        constexpr bool readState = true;
        constexpr bool senScanState = false;
        constexpr bool allEventMessageState = false;
        constexpr uint8_t assertionStatesLsb = 0;
        constexpr uint8_t assertionStatesMsb = 0;

        return ipmi::responseSuccess(senReading, reserved, readState,
                                     senScanState, allEventMessageState,
                                     assertionStatesLsb, assertionStatesMsb);
    }
}

get_sdr::GetSensorThresholdsResponse
    getSensorThresholds(ipmi::Context::ptr& ctx, uint8_t sensorNum)
{
    get_sdr::GetSensorThresholdsResponse resp{};
    constexpr auto warningThreshIntf =
        "xyz.openbmc_project.Sensor.Threshold.Warning";
    constexpr auto criticalThreshIntf =
        "xyz.openbmc_project.Sensor.Threshold.Critical";

    const auto iter = ipmi::sensor::sensors.find(sensorNum);
    const auto info = iter->second;

    std::string service;
    boost::system::error_code ec;
    ec = ipmi::getService(ctx, info.sensorInterface, info.sensorPath, service);
    if (ec)
    {
        return resp;
    }

    ipmi::PropertyMap warnThresholds;
    ec = ipmi::getAllDbusProperties(ctx, service, info.sensorPath,
                                    warningThreshIntf, warnThresholds);
    if (!ec)
    {
        double warnLow = std::visit(ipmi::VariantToDoubleVisitor(),
                                    warnThresholds["WarningLow"]);
        double warnHigh = std::visit(ipmi::VariantToDoubleVisitor(),
                                     warnThresholds["WarningHigh"]);

        if (std::isfinite(warnLow))
        {
            warnLow *= std::pow(10, info.scale - info.exponentR);
            resp.lowerNonCritical = static_cast<uint8_t>(
                (warnLow - info.scaledOffset) / info.coefficientM);
            resp.validMask |= static_cast<uint8_t>(
                ipmi::sensor::ThresholdMask::NON_CRITICAL_LOW_MASK);
        }

        if (std::isfinite(warnHigh))
        {
            warnHigh *= std::pow(10, info.scale - info.exponentR);
            resp.upperNonCritical = static_cast<uint8_t>(
                (warnHigh - info.scaledOffset) / info.coefficientM);
            resp.validMask |= static_cast<uint8_t>(
                ipmi::sensor::ThresholdMask::NON_CRITICAL_HIGH_MASK);
        }
    }

    ipmi::PropertyMap critThresholds;
    ec = ipmi::getAllDbusProperties(ctx, service, info.sensorPath,
                                    criticalThreshIntf, critThresholds);
    if (!ec)
    {
        double critLow = std::visit(ipmi::VariantToDoubleVisitor(),
                                    critThresholds["CriticalLow"]);
        double critHigh = std::visit(ipmi::VariantToDoubleVisitor(),
                                     critThresholds["CriticalHigh"]);

        if (std::isfinite(critLow))
        {
            critLow *= std::pow(10, info.scale - info.exponentR);
            resp.lowerCritical = static_cast<uint8_t>(
                (critLow - info.scaledOffset) / info.coefficientM);
            resp.validMask |= static_cast<uint8_t>(
                ipmi::sensor::ThresholdMask::CRITICAL_LOW_MASK);
        }

        if (std::isfinite(critHigh))
        {
            critHigh *= std::pow(10, info.scale - info.exponentR);
            resp.upperCritical = static_cast<uint8_t>(
                (critHigh - info.scaledOffset) / info.coefficientM);
            resp.validMask |= static_cast<uint8_t>(
                ipmi::sensor::ThresholdMask::CRITICAL_HIGH_MASK);
        }
    }

    return resp;
}

/** @brief implements the get sensor thresholds command
 *  @param ctx - IPMI context pointer
 *  @param sensorNum - sensor number
 *
 *  @returns IPMI completion code plus response data
 *   - validMask - threshold mask
 *   - lower non-critical threshold - IPMI messaging state
 *   - lower critical threshold - link authentication state
 *   - lower non-recoverable threshold - callback state
 *   - upper non-critical threshold
 *   - upper critical
 *   - upper non-recoverable
 */
ipmi::RspType<uint8_t, // validMask
              uint8_t, // lowerNonCritical
              uint8_t, // lowerCritical
              uint8_t, // lowerNonRecoverable
              uint8_t, // upperNonCritical
              uint8_t, // upperCritical
              uint8_t  // upperNonRecoverable
              >
    ipmiSensorGetSensorThresholds(ipmi::Context::ptr& ctx, uint8_t sensorNum)
{
    constexpr auto valueInterface = "xyz.openbmc_project.Sensor.Value";

    const auto iter = ipmi::sensor::sensors.find(sensorNum);
    if (iter == ipmi::sensor::sensors.end())
    {
        return ipmi::responseSensorInvalid();
    }

    const auto info = iter->second;

    // Proceed only if the sensor value interface is implemented.
    if (info.propertyInterfaces.find(valueInterface) ==
        info.propertyInterfaces.end())
    {
        // return with valid mask as 0
        return ipmi::responseSuccess();
    }

    auto it = sensorThresholdMap.find(sensorNum);
    if (it == sensorThresholdMap.end())
    {
        sensorThresholdMap[sensorNum] = getSensorThresholds(ctx, sensorNum);
    }

    const auto& resp = sensorThresholdMap[sensorNum];

    return ipmi::responseSuccess(resp.validMask, resp.lowerNonCritical,
                                 resp.lowerCritical, resp.lowerNonRecoverable,
                                 resp.upperNonCritical, resp.upperCritical,
                                 resp.upperNonRecoverable);
}

/** @brief implements the Set Sensor threshold command
 *  @param sensorNumber        - sensor number
 *  @param lowerNonCriticalThreshMask
 *  @param lowerCriticalThreshMask
 *  @param lowerNonRecovThreshMask
 *  @param upperNonCriticalThreshMask
 *  @param upperCriticalThreshMask
 *  @param upperNonRecovThreshMask
 *  @param reserved
 *  @param lowerNonCritical    - lower non-critical threshold
 *  @param lowerCritical       - Lower critical threshold
 *  @param lowerNonRecoverable - Lower non recovarable threshold
 *  @param upperNonCritical    - Upper non-critical threshold
 *  @param upperCritical       - Upper critical
 *  @param upperNonRecoverable - Upper Non-recoverable
 *
 *  @returns IPMI completion code
 */
ipmi::RspType<> ipmiSenSetSensorThresholds(
    ipmi::Context::ptr& ctx, uint8_t sensorNum, bool lowerNonCriticalThreshMask,
    bool lowerCriticalThreshMask, bool lowerNonRecovThreshMask,
    bool upperNonCriticalThreshMask, bool upperCriticalThreshMask,
    bool upperNonRecovThreshMask, uint2_t reserved, uint8_t lowerNonCritical,
    uint8_t lowerCritical, uint8_t, uint8_t upperNonCritical,
    uint8_t upperCritical, uint8_t)
{
    if (reserved)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    // lower nc and upper nc not suppported on any sensor
    if (lowerNonRecovThreshMask || upperNonRecovThreshMask)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    // if none of the threshold mask are set, nothing to do
    if (!(lowerNonCriticalThreshMask | lowerCriticalThreshMask |
          lowerNonRecovThreshMask | upperNonCriticalThreshMask |
          upperCriticalThreshMask | upperNonRecovThreshMask))
    {
        return ipmi::responseSuccess();
    }

    constexpr auto valueInterface = "xyz.openbmc_project.Sensor.Value";

    const auto iter = ipmi::sensor::sensors.find(sensorNum);
    if (iter == ipmi::sensor::sensors.end())
    {
        return ipmi::responseSensorInvalid();
    }

    const auto& info = iter->second;

    // Proceed only if the sensor value interface is implemented.
    if (info.propertyInterfaces.find(valueInterface) ==
        info.propertyInterfaces.end())
    {
        // return with valid mask as 0
        return ipmi::responseSuccess();
    }

    constexpr auto warningThreshIntf =
        "xyz.openbmc_project.Sensor.Threshold.Warning";
    constexpr auto criticalThreshIntf =
        "xyz.openbmc_project.Sensor.Threshold.Critical";

    std::string service;
    boost::system::error_code ec;
    ec = ipmi::getService(ctx, info.sensorInterface, info.sensorPath, service);
    if (ec)
    {
        return ipmi::responseResponseError();
    }
    // store a vector of property name, value to set, and interface
    std::vector<std::tuple<std::string, uint8_t, std::string>> thresholdsToSet;

    // define the indexes of the tuple
    constexpr uint8_t propertyName = 0;
    constexpr uint8_t thresholdValue = 1;
    constexpr uint8_t interface = 2;
    // verifiy all needed fields are present
    if (lowerCriticalThreshMask || upperCriticalThreshMask)
    {

        ipmi::PropertyMap findThreshold;
        ec = ipmi::getAllDbusProperties(ctx, service, info.sensorPath,
                                        criticalThreshIntf, findThreshold);

        if (!ec)
        {
            if (lowerCriticalThreshMask)
            {
                auto findLower = findThreshold.find("CriticalLow");
                if (findLower == findThreshold.end())
                {
                    return ipmi::responseInvalidFieldRequest();
                }
                thresholdsToSet.emplace_back("CriticalLow", lowerCritical,
                                             criticalThreshIntf);
            }
            if (upperCriticalThreshMask)
            {
                auto findUpper = findThreshold.find("CriticalHigh");
                if (findUpper == findThreshold.end())
                {
                    return ipmi::responseInvalidFieldRequest();
                }
                thresholdsToSet.emplace_back("CriticalHigh", upperCritical,
                                             criticalThreshIntf);
            }
        }
    }
    if (lowerNonCriticalThreshMask || upperNonCriticalThreshMask)
    {
        ipmi::PropertyMap findThreshold;
        ec = ipmi::getAllDbusProperties(ctx, service, info.sensorPath,
                                        warningThreshIntf, findThreshold);

        if (!ec)
        {
            if (lowerNonCriticalThreshMask)
            {
                auto findLower = findThreshold.find("WarningLow");
                if (findLower == findThreshold.end())
                {
                    return ipmi::responseInvalidFieldRequest();
                }
                thresholdsToSet.emplace_back("WarningLow", lowerNonCritical,
                                             warningThreshIntf);
            }
            if (upperNonCriticalThreshMask)
            {
                auto findUpper = findThreshold.find("WarningHigh");
                if (findUpper == findThreshold.end())
                {
                    return ipmi::responseInvalidFieldRequest();
                }
                thresholdsToSet.emplace_back("WarningHigh", upperNonCritical,
                                             warningThreshIntf);
            }
        }
    }
    for (const auto& property : thresholdsToSet)
    {
        // from section 36.3 in the IPMI Spec, assume all linear
        double valueToSet =
            ((info.coefficientM * std::get<thresholdValue>(property)) +
             (info.scaledOffset * std::pow(10.0, info.scale))) *
            std::pow(10.0, info.exponentR);
        ipmi::setDbusProperty(
            ctx, service, info.sensorPath, std::get<interface>(property),
            std::get<propertyName>(property), ipmi::Value(valueToSet));
    }

    // Invalidate the cache
    sensorThresholdMap.erase(sensorNum);
    return ipmi::responseSuccess();
}

/** @brief implements the get SDR Info command
 *  @param count - Operation
 *
 *  @returns IPMI completion code plus response data
 *   - sdrCount - sensor/SDR count
 *   - lunsAndDynamicPopulation - static/Dynamic sensor population flag
 */
ipmi::RspType<uint8_t, // respcount
              uint8_t  // dynamic population flags
              >
    ipmiSensorGetDeviceSdrInfo(std::optional<uint8_t> count)
{
    uint8_t sdrCount;
    // multiple LUNs not supported.
    constexpr uint8_t lunsAndDynamicPopulation = 1;
    constexpr uint8_t getSdrCount = 0x01;
    constexpr uint8_t getSensorCount = 0x00;

    if (count.value_or(0) == getSdrCount)
    {
        // Get SDR count. This returns the total number of SDRs in the device.
        const auto& entityRecords =
            ipmi::sensor::EntityInfoMapContainer::getContainer()
                ->getIpmiEntityRecords();
        sdrCount =
            ipmi::sensor::sensors.size() + frus.size() + entityRecords.size();
    }
    else if (count.value_or(0) == getSensorCount)
    {
        // Get Sensor count. This returns the number of sensors
        sdrCount = ipmi::sensor::sensors.size();
    }
    else
    {
        return ipmi::responseInvalidCommandOnLun();
    }

    return ipmi::responseSuccess(sdrCount, lunsAndDynamicPopulation);
}

/** @brief implements the reserve SDR command
 *  @returns IPMI completion code plus response data
 *   - reservationID - reservation ID
 */
ipmi::RspType<uint16_t> ipmiSensorReserveSdr()
{
    // A constant reservation ID is okay until we implement add/remove SDR.
    constexpr uint16_t reservationID = 1;

    return ipmi::responseSuccess(reservationID);
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
                                     ipmi_data_len_t)
{
    /* Functional sensor case */
    if (isAnalogSensor(info->propertyInterfaces.begin()->first))
    {
        body->sensor_units_1 = info->sensorUnits1; // default is 0. unsigned, no
                                                   // rate, no modifier, not a %
        /* Unit info */
        setUnitFieldsForObject(info, body);

        get_sdr::body::set_b(info->coefficientB, body);
        get_sdr::body::set_m(info->coefficientM, body);
        get_sdr::body::set_b_exp(info->exponentB, body);
        get_sdr::body::set_r_exp(info->exponentR, body);

        get_sdr::body::set_id_type(0b00, body); // 00 = unicode
    }

    /* ID string */
    auto id_string = info->sensorName;

    if (id_string.empty())
    {
        id_string = info->sensorNameFunc(*info);
    }

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
        const auto& entityRecords =
            ipmi::sensor::EntityInfoMapContainer::getContainer()
                ->getIpmiEntityRecords();
        auto next_record_id =
            (entityRecords.size())
                ? entityRecords.begin()->first + ENTITY_RECORD_ID_START
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

    const auto& entityRecords =
        ipmi::sensor::EntityInfoMapContainer::getContainer()
            ->getIpmiEntityRecords();
    auto entity = entityRecords.begin();
    uint8_t entityRecordID;
    auto recordID = get_sdr::request::get_record_id(req);

    entityRecordID = recordID - ENTITY_RECORD_ID_START;
    entity = entityRecords.find(entityRecordID);
    if (entity == entityRecords.end())
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

    if (++entity == entityRecords.end())
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

ipmi_ret_t ipmi_sen_get_sdr(ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t request,
                            ipmi_response_t response, ipmi_data_len_t data_len,
                            ipmi_context_t)
{
    ipmi_ret_t ret = IPMI_CC_OK;
    get_sdr::GetSdrReq* req = (get_sdr::GetSdrReq*)request;
    get_sdr::GetSdrResp* resp = (get_sdr::GetSdrResp*)response;

    // Note: we use an iterator so we can provide the next ID at the end of
    // the call.
    auto sensor = ipmi::sensor::sensors.begin();
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
            sensor = ipmi::sensor::sensors.find(recordID);
            if (sensor == ipmi::sensor::sensors.end())
            {
                return IPMI_CC_SENSOR_INVALID;
            }
        }
    }

    uint8_t sensor_id = sensor->first;

    auto it = sdrCacheMap.find(sensor_id);
    if (it == sdrCacheMap.end())
    {
        /* Header */
        get_sdr::SensorDataFullRecord record = {};
        get_sdr::header::set_record_id(sensor_id, &(record.header));
        record.header.sdr_version = 0x51; // Based on IPMI Spec v2.0 rev 1.1
        record.header.record_type = get_sdr::SENSOR_DATA_FULL_RECORD;
        record.header.record_length = sizeof(record.key) + sizeof(record.body);

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
        populate_record_from_dbus(&(record.body), &(sensor->second), data_len);
        sdrCacheMap[sensor_id] = std::move(record);
    }

    const auto& record = sdrCacheMap[sensor_id];

    if (++sensor == ipmi::sensor::sensors.end())
    {
        // we have reached till end of sensor, so assign the next record id
        // to 256(Max Sensor ID = 255) + FRU ID(may start with 0).
        auto next_record_id = (frus.size())
                                  ? frus.begin()->first + FRU_RECORD_ID_START
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
                reinterpret_cast<const uint8_t*>(&record) + req->offset,
                *data_len);

    // data_len should include the LSB and MSB:
    *data_len +=
        sizeof(resp->next_record_id_lsb) + sizeof(resp->next_record_id_msb);

    return ret;
}

static bool isFromSystemChannel()
{
    // TODO we could not figure out where the request is from based on IPMI
    // command handler parameters. because of it, we can not differentiate
    // request from SMS/SMM or IPMB channel
    return true;
}

ipmi_ret_t ipmicmdPlatformEvent(ipmi_netfn_t, ipmi_cmd_t,
                                ipmi_request_t request, ipmi_response_t,
                                ipmi_data_len_t dataLen, ipmi_context_t)
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

    sdbusplus::bus_t dbus(bus);
    std::string service =
        ipmi::getService(dbus, ipmiSELAddInterface, ipmiSELPath);
    sdbusplus::message_t writeSEL = dbus.new_method_call(
        service.c_str(), ipmiSELPath, ipmiSELAddInterface, "IpmiSelAdd");
    writeSEL.append(ipmiSELAddMessage, sensorPath, eventData, assert,
                    generatorID);
    try
    {
        dbus.call(writeSEL);
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    return IPMI_CC_OK;
}

void register_netfn_sen_functions()
{
    // Handlers with dbus-sdr handler implementation.
    // Do not register the hander if it dynamic sensors stack is used.

#ifndef FEATURE_DYNAMIC_SENSORS

#ifdef FEATURE_SENSORS_OVERRIDE
    initSensorOverride();
    initSensorOverrideMatches();
#endif

#ifdef FEATURE_SENSORS_CACHE
    // Initialize the sensor matches
    initSensorMatches();
#endif

    // <Set Sensor Reading and Event Status>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdSetSensorReadingAndEvtSts,
                          ipmi::Privilege::Operator, ipmiSetSensorReading);
    // <Get Sensor Reading>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdGetSensorReading,
                          ipmi::Privilege::User, ipmiSensorGetSensorReading);

    // <Reserve Device SDR Repository>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdReserveDeviceSdrRepository,
                          ipmi::Privilege::User, ipmiSensorReserveSdr);

    // <Get Device SDR Info>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdGetDeviceSdrInfo,
                          ipmi::Privilege::User, ipmiSensorGetDeviceSdrInfo);

    // <Get Sensor Thresholds>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdGetSensorThreshold,
                          ipmi::Privilege::User, ipmiSensorGetSensorThresholds);

    // <Set Sensor Thresholds>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdSetSensorThreshold,
                          ipmi::Privilege::User, ipmiSenSetSensorThresholds);

    // <Get Device SDR>
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_GET_DEVICE_SDR, nullptr,
                           ipmi_sen_get_sdr, PRIVILEGE_USER);

#endif

    // Common Handers used by both implementation.

    // <Platform Event Message>
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_PLATFORM_EVENT, nullptr,
                           ipmicmdPlatformEvent, PRIVILEGE_OPERATOR);

    // <Get Sensor Type>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdGetSensorType,
                          ipmi::Privilege::User, ipmiGetSensorType);

    return;
}
