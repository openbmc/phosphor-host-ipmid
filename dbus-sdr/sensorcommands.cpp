/*
// Copyright (c) 2017 2018 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include "config.h"

#include "dbus-sdr/sensorcommands.hpp"

#include "dbus-sdr/sdrutils.hpp"
#include "dbus-sdr/sensorutils.hpp"
#include "dbus-sdr/storagecommands.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/container/flat_map.hpp>
#include <ipmid/api.hpp>
#include <ipmid/entity_map_json.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus.hpp>
#include <user_channel/channel_layer.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstring>
#include <format>
#include <iostream>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>

#ifdef FEATURE_HYBRID_SENSORS

#include "sensordatahandler.hpp"
namespace ipmi
{
namespace sensor
{
extern const IdInfoMap sensors;
} // namespace sensor
} // namespace ipmi
#endif
namespace ipmi
{
namespace dcmi
{
// Refer Table 6-14, DCMI Entity ID Extension, DCMI v1.5 spec
static const std::map<uint8_t, uint8_t> validEntityId{
    {0x40, 0x37}, {0x37, 0x40}, {0x41, 0x03},
    {0x03, 0x41}, {0x42, 0x07}, {0x07, 0x42}};
constexpr uint8_t temperatureSensorType = 0x01;
constexpr uint8_t maxRecords = 8;
} // namespace dcmi
} // namespace ipmi
constexpr std::array<const char*, 7> suffixes = {
    "_Output_Voltage", "_Input_Voltage", "_Output_Current", "_Input_Current",
    "_Output_Power",   "_Input_Power",   "_Temperature"};
namespace ipmi
{

using phosphor::logging::entry;
using phosphor::logging::level;
using phosphor::logging::log;

static constexpr int sensorMapUpdatePeriod = 10;
static constexpr int sensorMapSdrUpdatePeriod = 60;

// BMC I2C address is generally at 0x20
static constexpr uint8_t bmcI2CAddr = 0x20;

constexpr size_t maxSDRTotalSize =
    76; // Largest SDR Record Size (type 01) + SDR Overheader Size
constexpr static const uint32_t noTimestamp = 0xFFFFFFFF;

static uint16_t sdrReservationID;
static uint32_t sdrLastAdd = noTimestamp;
static uint32_t sdrLastRemove = noTimestamp;
static constexpr size_t lastRecordIndex = 0xFFFF;

// The IPMI spec defines four Logical Units (LUN), each capable of supporting
// 255 sensors. The 256 values assigned to LUN 2 are special and are not used
// for general purpose sensors. Each LUN reserves location 0xFF. The maximum
// number of IPMI sensors are LUN 0 + LUN 1 + LUN 3, less the reserved
// location.
static constexpr size_t maxIPMISensors = ((3 * 256) - (3 * 1));

static constexpr uint8_t lun0 = 0x0;
static constexpr uint8_t lun1 = 0x1;
static constexpr uint8_t lun3 = 0x3;

static constexpr size_t lun0MaxSensorNum = 0xfe;
static constexpr size_t lun1MaxSensorNum = 0x1fe;
static constexpr size_t lun3MaxSensorNum = 0x3fe;
static constexpr int GENERAL_ERROR = -1;

static boost::container::flat_map<std::string, ObjectValueTree> SensorCache;

// Specify the comparison required to sort and find char* map objects
struct CmpStr
{
    bool operator()(const char* a, const char* b) const
    {
        return std::strcmp(a, b) < 0;
    }
};
const static boost::container::flat_map<const char*, SensorUnits, CmpStr>
    sensorUnits{{{"temperature", SensorUnits::degreesC},
                 {"voltage", SensorUnits::volts},
                 {"current", SensorUnits::amps},
                 {"fan_tach", SensorUnits::rpm},
                 {"power", SensorUnits::watts},
                 {"energy", SensorUnits::joules}}};

void registerSensorFunctions() __attribute__((constructor));

static sdbusplus::bus::match_t sensorAdded(
    *getSdBus(),
    "type='signal',member='InterfacesAdded',arg0path='/xyz/openbmc_project/"
    "sensors/'",
    [](sdbusplus::message_t&) {
        getSensorTree().clear();
        getIpmiDecoratorPaths(/*ctx=*/std::nullopt).reset();
        sdrLastAdd = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    });

static sdbusplus::bus::match_t sensorRemoved(
    *getSdBus(),
    "type='signal',member='InterfacesRemoved',arg0path='/xyz/openbmc_project/"
    "sensors/'",
    [](sdbusplus::message_t&) {
        getSensorTree().clear();
        getIpmiDecoratorPaths(/*ctx=*/std::nullopt).reset();
        sdrLastRemove = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();
    });

ipmi_ret_t getSensorConnection(ipmi::Context::ptr ctx, uint8_t sensnum,
                               std::string& connection, std::string& path,
                               std::vector<std::string>* interfaces)
{
    auto& sensorTree = getSensorTree();
    if (!getSensorSubtree(sensorTree) && sensorTree.empty())
    {
        return IPMI_CC_RESPONSE_ERROR;
    }

    if (ctx == nullptr)
    {
        return IPMI_CC_RESPONSE_ERROR;
    }

    path = getPathFromSensorNumber((ctx->lun << 8) | sensnum);
    if (path.empty())
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    for (const auto& sensor : sensorTree)
    {
        if (path == sensor.first)
        {
            connection = sensor.second.begin()->first;
            if (interfaces)
                *interfaces = sensor.second.begin()->second;
            break;
        }
    }

    return 0;
}

SensorSubTree& getSensorTree()
{
    static SensorSubTree sensorTree;
    return sensorTree;
}

// this keeps track of deassertions for sensor event status command. A
// deasertion can only happen if an assertion was seen first.
static boost::container::flat_map<
    std::string, boost::container::flat_map<std::string, std::optional<bool>>>
    thresholdDeassertMap;

static sdbusplus::bus::match_t thresholdChanged(
    *getSdBus(),
    "type='signal',member='PropertiesChanged',interface='org.freedesktop.DBus."
    "Properties',arg0namespace='xyz.openbmc_project.Sensor.Threshold'",
    [](sdbusplus::message_t& m) {
        boost::container::flat_map<std::string, std::variant<bool, double>>
            values;
        m.read(std::string(), values);

        auto findAssert =
            std::find_if(values.begin(), values.end(), [](const auto& pair) {
                return pair.first.find("Alarm") != std::string::npos;
            });
        if (findAssert != values.end())
        {
            auto ptr = std::get_if<bool>(&(findAssert->second));
            if (ptr == nullptr)
            {
                lg2::error("thresholdChanged: Assert non bool");
                return;
            }
            if (*ptr)
            {
                lg2::info(
                    "thresholdChanged: Assert, sensor path: {SENSOR_PATH}",
                    "SENSOR_PATH", m.get_path());
                thresholdDeassertMap[m.get_path()][findAssert->first] = *ptr;
            }
            else
            {
                auto& value =
                    thresholdDeassertMap[m.get_path()][findAssert->first];
                if (value)
                {
                    lg2::info(
                        "thresholdChanged: deassert, sensor path: {SENSOR_PATH}",
                        "SENSOR_PATH", m.get_path());
                    value = *ptr;
                }
            }
        }
    });

namespace sensor
{
static constexpr const char* vrInterface =
    "xyz.openbmc_project.Control.VoltageRegulatorMode";
static constexpr const char* sensorInterface =
    "xyz.openbmc_project.Sensor.Value";
} // namespace sensor

static void getSensorMaxMin(const DbusInterfaceMap& sensorMap, double& max,
                            double& min)
{
    max = 127;
    min = -128;

    auto sensorObject = sensorMap.find(sensor::sensorInterface);
    auto critical =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Critical");
    auto warning =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Warning");

    if (sensorObject != sensorMap.end())
    {
        auto maxMap = sensorObject->second.find("MaxValue");
        auto minMap = sensorObject->second.find("MinValue");

        if (maxMap != sensorObject->second.end())
        {
            max = std::visit(VariantToDoubleVisitor(), maxMap->second);
        }
        if (minMap != sensorObject->second.end())
        {
            min = std::visit(VariantToDoubleVisitor(), minMap->second);
        }
    }
    if (critical != sensorMap.end())
    {
        auto lower = critical->second.find("CriticalLow");
        auto upper = critical->second.find("CriticalHigh");
        if (lower != critical->second.end())
        {
            double value = std::visit(VariantToDoubleVisitor(), lower->second);
            if (std::isfinite(value))
            {
                min = std::fmin(value, min);
            }
        }
        if (upper != critical->second.end())
        {
            double value = std::visit(VariantToDoubleVisitor(), upper->second);
            if (std::isfinite(value))
            {
                max = std::fmax(value, max);
            }
        }
    }
    if (warning != sensorMap.end())
    {
        auto lower = warning->second.find("WarningLow");
        auto upper = warning->second.find("WarningHigh");
        if (lower != warning->second.end())
        {
            double value = std::visit(VariantToDoubleVisitor(), lower->second);
            if (std::isfinite(value))
            {
                min = std::fmin(value, min);
            }
        }
        if (upper != warning->second.end())
        {
            double value = std::visit(VariantToDoubleVisitor(), upper->second);
            if (std::isfinite(value))
            {
                max = std::fmax(value, max);
            }
        }
    }
}

static bool getSensorMap(ipmi::Context::ptr ctx, std::string sensorConnection,
                         std::string sensorPath, DbusInterfaceMap& sensorMap,
                         int updatePeriod = sensorMapUpdatePeriod)
{
#ifdef FEATURE_HYBRID_SENSORS
    if (auto sensor = findStaticSensor(sensorPath);
        sensor != ipmi::sensor::sensors.end() &&
        getSensorEventTypeFromPath(sensorPath) !=
            static_cast<uint8_t>(SensorEventTypeCodes::threshold))
    {
        // If the incoming sensor is a discrete sensor, it might fail in
        // getManagedObjects(), return true, and use its own getFunc to get
        // value.
        return true;
    }
#endif

    static boost::container::flat_map<
        std::string, std::chrono::time_point<std::chrono::steady_clock>>
        updateTimeMap;

    auto updateFind = updateTimeMap.find(sensorConnection);
    auto lastUpdate = std::chrono::time_point<std::chrono::steady_clock>();
    if (updateFind != updateTimeMap.end())
    {
        lastUpdate = updateFind->second;
    }

    auto now = std::chrono::steady_clock::now();

    if (std::chrono::duration_cast<std::chrono::seconds>(now - lastUpdate)
            .count() > updatePeriod)
    {
        bool found = false;

        // Object managers for different kinds of OpenBMC DBus interfaces.
        // Documented in the phosphor-dbus-interfaces repository.
        const char* paths[] = {
            "/xyz/openbmc_project/sensors",
            "/xyz/openbmc_project/vr",
        };
        constexpr size_t num_paths = sizeof(paths) / sizeof(paths[0]);
        ObjectValueTree allManagedObjects;

        for (size_t i = 0; i < num_paths; i++)
        {
            ObjectValueTree managedObjects;
            boost::system::error_code ec = getManagedObjects(
                ctx, sensorConnection.c_str(), paths[i], managedObjects);
            if (ec)
            {
                continue;
            }
            allManagedObjects.merge(managedObjects);
            found = true;
        }

        if (!found)
        {
            lg2::error("GetMangagedObjects for getSensorMap failed, "
                       "service: {SERVICE}",
                       "SERVICE", sensorConnection);

            return false;
        }

        SensorCache[sensorConnection] = allManagedObjects;
        // Update time after finish building the map which allow the
        // data to be cached for updatePeriod plus the build time.
        updateTimeMap[sensorConnection] = std::chrono::steady_clock::now();
    }
    auto connection = SensorCache.find(sensorConnection);
    if (connection == SensorCache.end())
    {
        return false;
    }
    auto path = connection->second.find(sensorPath);
    if (path == connection->second.end())
    {
        return false;
    }
    sensorMap = path->second;

    return true;
}

namespace sensor
{
// Read VR profiles from sensor(daemon) interface
static std::optional<std::vector<std::string>>
    getSupportedVrProfiles(const ipmi::DbusInterfaceMap::mapped_type& object)
{
    // get VR mode profiles from Supported Interface
    auto supportedProperty = object.find("Supported");
    if (supportedProperty == object.end() ||
        object.find("Selected") == object.end())
    {
        lg2::error("Missing the required Supported and Selected properties");
        return std::nullopt;
    }

    const auto profilesPtr =
        std::get_if<std::vector<std::string>>(&supportedProperty->second);

    if (profilesPtr == nullptr)
    {
        lg2::error("property is not array of string");
        return std::nullopt;
    }
    return *profilesPtr;
}

// Calculate VR Mode from input IPMI discrete event bytes
static std::optional<std::string> calculateVRMode(
    uint15_t assertOffset, const ipmi::DbusInterfaceMap::mapped_type& VRObject)
{
    // get VR mode profiles from Supported Interface
    auto profiles = getSupportedVrProfiles(VRObject);
    if (!profiles)
    {
        return std::nullopt;
    }

    // interpret IPMI cmd bits into profiles' index
    long unsigned int index = 0;
    // only one bit should be set and the highest bit should not be used.
    if (assertOffset == 0 || assertOffset == (1u << 15) ||
        (assertOffset & (assertOffset - 1)))
    {
        lg2::error("IPMI cmd format incorrect, bytes: {BYTES}", "BYTES",
                   lg2::hex, static_cast<uint16_t>(assertOffset));
        return std::nullopt;
    }

    while (assertOffset != 1)
    {
        assertOffset >>= 1;
        index++;
    }

    if (index >= profiles->size())
    {
        lg2::error("profile index out of boundary");
        return std::nullopt;
    }

    return profiles->at(index);
}

// Calculate sensor value from IPMI reading byte
static std::optional<double>
    calculateValue(uint8_t reading, const ipmi::DbusInterfaceMap& sensorMap,
                   const ipmi::DbusInterfaceMap::mapped_type& valueObject)
{
    if (valueObject.find("Value") == valueObject.end())
    {
        lg2::error("Missing the required Value property");
        return std::nullopt;
    }

    double max = 0;
    double min = 0;
    getSensorMaxMin(sensorMap, max, min);

    int16_t mValue = 0;
    int16_t bValue = 0;
    int8_t rExp = 0;
    int8_t bExp = 0;
    bool bSigned = false;

    if (!getSensorAttributes(max, min, mValue, rExp, bValue, bExp, bSigned))
    {
        return std::nullopt;
    }

    double value = bSigned ? ((int8_t)reading) : reading;

    value *= ((double)mValue);
    value += ((double)bValue) * std::pow(10.0, bExp);
    value *= std::pow(10.0, rExp);

    return value;
}

// Extract file name from sensor path as the sensors SDR ID. Simplify the name
// if it is too long.
std::string parseSdrIdFromPath(const std::string& path)
{
    std::string name;
    size_t nameStart = path.rfind("/");
    if (nameStart != std::string::npos)
    {
        name = path.substr(nameStart + 1, std::string::npos - nameStart);
    }

    if (name.size() > FULL_RECORD_ID_STR_MAX_LENGTH)
    {
#ifdef SHORTNAME_REMOVE_SUFFIX
        for (const auto& suffix : suffixes)
        {
            if (boost::ends_with(name, suffix))
            {
                boost::replace_all(name, suffix, "");
                break;
            }
        }
#endif
#ifdef SHORTNAME_REPLACE_WORDS
        constexpr std::array<std::pair<const char*, const char*>, 2>
            replaceWords = {std::make_pair("Output", "Out"),
                            std::make_pair("Input", "In")};
        for (const auto& [find, replace] : replaceWords)
        {
            boost::replace_all(name, find, replace);
        }
#endif

        // as a backup and if nothing else is configured
        name.resize(FULL_RECORD_ID_STR_MAX_LENGTH);
    }
    return name;
}

bool getVrEventStatus(ipmi::Context::ptr ctx, const std::string& connection,
                      const std::string& path,
                      const ipmi::DbusInterfaceMap::mapped_type& object,
                      std::bitset<16>& assertions)
{
    auto profiles = sensor::getSupportedVrProfiles(object);
    if (!profiles)
    {
        return false;
    }
    std::string mode;

    auto ec = getDbusProperty(ctx, connection, path, sensor::vrInterface,
                              "Selected", mode);
    if (ec)
    {
        lg2::error("Failed to get Selected, path: {PATH}, "
                   "interface: {INTERFACE}, error: {ERROR}",
                   "PATH", path, "INTERFACE", sensor::sensorInterface, "ERROR",
                   ec.message());
        return false;
    }

    auto itr = std::find(profiles->begin(), profiles->end(), mode);
    if (itr == profiles->end())
    {
        lg2::error("VR mode doesn't match any of its profiles, path: {PATH}",
                   "PATH", path);
        return false;
    }
    std::size_t index =
        static_cast<std::size_t>(std::distance(profiles->begin(), itr));

    // map index to response event assertion bit.
    if (index < 16)
    {
        assertions.set(index);
    }
    else
    {
        lg2::error("VR profile index reaches max assertion bit, "
                   "path: {PATH}, index: {INDEX}",
                   "PATH", path, "INDEX", index);
        return false;
    }
    if constexpr (debug)
    {
        std::cerr << "VR sensor " << sensor::parseSdrIdFromPath(path)
                  << " mode is: [" << index << "] " << mode << std::endl;
    }
    return true;
}

/*
 * Handle every Sensor Data Record besides Type 01
 *
 * The D-Bus sensors work well for generating Type 01 SDRs.
 * After the Type 01 sensors are processed the remaining sensor types require
 * special handling. Each BMC vendor is going to have their own requirements for
 * insertion of non-Type 01 records.
 * Manage non-Type 01 records:
 *
 * Create a new file: dbus-sdr/sensorcommands_oem.cpp
 * Populate it with the two weakly linked functions below, without adding the
 * 'weak' attribute definition prior to the function definition.
 *    getOtherSensorsCount(...)
 *    getOtherSensorsDataRecord(...)
 *    Example contents are provided in the weak definitions below
 *    Enable 'sensors-oem' in your phosphor-ipmi-host bbappend file
 *      'EXTRA_OEMESON:append = " -Dsensors-oem=enabled"'
 * The contents of the sensorcommands_oem.cpp file will then override the code
 * provided below.
 */

size_t getOtherSensorsCount(ipmi::Context::ptr ctx) __attribute__((weak));
size_t getOtherSensorsCount(ipmi::Context::ptr ctx)
{
    size_t fruCount = 0;

    ipmi::Cc ret = ipmi::storage::getFruSdrCount(ctx, fruCount);
    if (ret != ipmi::ccSuccess)
    {
        lg2::error("getOtherSensorsCount: getFruSdrCount error");
        return std::numeric_limits<size_t>::max();
    }

    const auto& entityRecords =
        ipmi::sensor::EntityInfoMapContainer::getContainer()
            ->getIpmiEntityRecords();
    size_t entityCount = entityRecords.size();

    return fruCount + ipmi::storage::type12Count + entityCount;
}

int getOtherSensorsDataRecord(ipmi::Context::ptr ctx, uint16_t recordID,
                              std::vector<uint8_t>& recordData)
    __attribute__((weak));
int getOtherSensorsDataRecord(ipmi::Context::ptr ctx, uint16_t recordID,
                              std::vector<uint8_t>& recordData)
{
    size_t otherCount{ipmi::sensor::getOtherSensorsCount(ctx)};
    if (otherCount == std::numeric_limits<size_t>::max())
    {
        return GENERAL_ERROR;
    }
    const auto& entityRecords =
        ipmi::sensor::EntityInfoMapContainer::getContainer()
            ->getIpmiEntityRecords();

    size_t sdrIndex(recordID - ipmi::getNumberOfSensors());
    size_t entityCount{entityRecords.size()};
    size_t fruCount{otherCount - ipmi::storage::type12Count - entityCount};

    if (sdrIndex > otherCount)
    {
        return std::numeric_limits<int>::min();
    }
    else if (sdrIndex >= fruCount + ipmi::storage::type12Count)
    {
        // handle type 8 entity map records
        ipmi::sensor::EntityInfoMap::const_iterator entity =
            entityRecords.find(static_cast<uint8_t>(
                sdrIndex - fruCount - ipmi::storage::type12Count));

        if (entity == entityRecords.end())
        {
            return GENERAL_ERROR;
        }
        recordData = ipmi::storage::getType8SDRs(entity, recordID);
    }
    else if (sdrIndex >= fruCount)
    {
        // handle type 12 hardcoded records
        size_t type12Index = sdrIndex - fruCount;
        if (type12Index >= ipmi::storage::type12Count)
        {
            lg2::error("getSensorDataRecord: type12Index error");
            return GENERAL_ERROR;
        }
        recordData = ipmi::storage::getType12SDRs(type12Index, recordID);
    }
    else
    {
        // handle fru records
        get_sdr::SensorDataFruRecord data;
        if (ipmi::Cc ret = ipmi::storage::getFruSdrs(ctx, sdrIndex, data);
            ret != IPMI_CC_OK)
        {
            return GENERAL_ERROR;
        }
        data.header.record_id_msb = recordID >> 8;
        data.header.record_id_lsb = recordID & 0xFF;
        recordData.insert(recordData.end(), reinterpret_cast<uint8_t*>(&data),
                          reinterpret_cast<uint8_t*>(&data) + sizeof(data));
    }

    return 0;
}

} // namespace sensor

ipmi::RspType<> ipmiSenPlatformEvent(ipmi::Context::ptr ctx,
                                     ipmi::message::Payload& p)
{
    constexpr const uint8_t validEnvmRev = 0x04;
    constexpr const uint8_t lastSensorType = 0x2C;
    constexpr const uint8_t oemReserved = 0xC0;

    uint8_t sysgeneratorID = 0;
    uint8_t evmRev = 0;
    uint8_t sensorType = 0;
    uint8_t sensorNum = 0;
    uint8_t eventType = 0;
    uint8_t eventData1 = 0;
    std::optional<uint8_t> eventData2 = 0;
    std::optional<uint8_t> eventData3 = 0;
    [[maybe_unused]] uint16_t generatorID = 0;
    ipmi::ChannelInfo chInfo;

    if (ipmi::getChannelInfo(ctx->channel, chInfo) != ipmi::ccSuccess)
    {
        lg2::error("Failed to get Channel Info, channel: {CHANNEL}", "CHANNEL",
                   ctx->channel);
        return ipmi::responseUnspecifiedError();
    }

    if (static_cast<ipmi::EChannelMediumType>(chInfo.mediumType) ==
        ipmi::EChannelMediumType::systemInterface)
    {
        p.unpack(sysgeneratorID, evmRev, sensorType, sensorNum, eventType,
                 eventData1, eventData2, eventData3);
        constexpr const uint8_t isSoftwareID = 0x01;
        if (!(sysgeneratorID & isSoftwareID))
        {
            return ipmi::responseInvalidFieldRequest();
        }
        // Refer to IPMI Spec Table 32: SEL Event Records
        generatorID = (ctx->channel << 12) // Channel
                      | (0x0 << 10)        // Reserved
                      | (0x0 << 8)         // 0x0 for sys-soft ID
                      | sysgeneratorID;
    }
    else
    {
        p.unpack(evmRev, sensorType, sensorNum, eventType, eventData1,
                 eventData2, eventData3);
        // Refer to IPMI Spec Table 32: SEL Event Records
        generatorID = (ctx->channel << 12)      // Channel
                      | (0x0 << 10)             // Reserved
                      | ((ctx->lun & 0x3) << 8) // Lun
                      | (ctx->rqSA << 1);
    }

    if (!p.fullyUnpacked())
    {
        return ipmi::responseReqDataLenInvalid();
    }

    // Check for valid evmRev and Sensor Type(per Table 42 of spec)
    if (evmRev != validEnvmRev)
    {
        return ipmi::responseInvalidFieldRequest();
    }
    if ((sensorType > lastSensorType) && (sensorType < oemReserved))
    {
        return ipmi::responseInvalidFieldRequest();
    }

    return ipmi::responseSuccess();
}

ipmi::RspType<> ipmiSetSensorReading(
    ipmi::Context::ptr ctx, uint8_t sensorNumber, uint8_t, uint8_t reading,
    uint15_t assertOffset, bool, uint15_t, bool, uint8_t, uint8_t, uint8_t)
{
    std::string connection;
    std::string path;
    std::vector<std::string> interfaces;

    ipmi::Cc status =
        getSensorConnection(ctx, sensorNumber, connection, path, &interfaces);
    if (status)
    {
        return ipmi::response(status);
    }

    // we can tell the sensor type by its interface type
    if (std::find(interfaces.begin(), interfaces.end(),
                  sensor::sensorInterface) != interfaces.end())
    {
        DbusInterfaceMap sensorMap;
        if (!getSensorMap(ctx, connection, path, sensorMap))
        {
            return ipmi::responseResponseError();
        }
        auto sensorObject = sensorMap.find(sensor::sensorInterface);
        if (sensorObject == sensorMap.end())
        {
            return ipmi::responseResponseError();
        }

        // Only allow external SetSensor if write permission granted
        if (!details::sdrWriteTable.getWritePermission(
                (ctx->lun << 8) | sensorNumber))
        {
            return ipmi::responseResponseError();
        }

        auto value =
            sensor::calculateValue(reading, sensorMap, sensorObject->second);
        if (!value)
        {
            return ipmi::responseResponseError();
        }

        if constexpr (debug)
        {
            lg2::info("IPMI SET_SENSOR, sensor number: {SENSOR_NUM}, "
                      "byte: {BYTE}, value: {VALUE}",
                      "SENSOR_NUM", sensorNumber, "BYTE", (unsigned int)reading,
                      "VALUE", *value);
        }

        boost::system::error_code ec =
            setDbusProperty(ctx, connection, path, sensor::sensorInterface,
                            "Value", ipmi::Value(*value));

        // setDbusProperty intended to resolve dbus exception/rc within the
        // function but failed to achieve that. Catch exception in the ipmi
        // callback functions for now (e.g. ipmiSetSensorReading).
        if (ec)
        {
            lg2::error("Failed to set Value, path: {PATH}, "
                       "interface: {INTERFACE}, ERROR: {ERROR}",
                       "PATH", path, "INTERFACE", sensor::sensorInterface,
                       "ERROR", ec.message());
            return ipmi::responseResponseError();
        }
        return ipmi::responseSuccess();
    }

    if (std::find(interfaces.begin(), interfaces.end(), sensor::vrInterface) !=
        interfaces.end())
    {
        DbusInterfaceMap sensorMap;
        if (!getSensorMap(ctx, connection, path, sensorMap))
        {
            return ipmi::responseResponseError();
        }
        auto sensorObject = sensorMap.find(sensor::vrInterface);
        if (sensorObject == sensorMap.end())
        {
            return ipmi::responseResponseError();
        }

        // VR sensors are treated as a special case and we will not check the
        // write permission for VR sensors, since they always deemed writable
        // and permission table are not applied to VR sensors.
        auto vrMode =
            sensor::calculateVRMode(assertOffset, sensorObject->second);
        if (!vrMode)
        {
            return ipmi::responseResponseError();
        }
        boost::system::error_code ec = setDbusProperty(
            ctx, connection, path, sensor::vrInterface, "Selected", *vrMode);
        // setDbusProperty intended to resolve dbus exception/rc within the
        // function but failed to achieve that. Catch exception in the ipmi
        // callback functions for now (e.g. ipmiSetSensorReading).
        if (ec)
        {
            lg2::error("Failed to set Selected, path: {PATH}, "
                       "interface: {INTERFACE}, ERROR: {ERROR}",
                       "PATH", path, "INTERFACE", sensor::sensorInterface,
                       "ERROR", ec.message());
        }
        return ipmi::responseSuccess();
    }

    lg2::error("unknown sensor type, path: {PATH}", "PATH", path);
    return ipmi::responseResponseError();
}

ipmi::RspType<uint8_t, uint8_t, uint8_t, std::optional<uint8_t>>
    ipmiSenGetSensorReading(ipmi::Context::ptr ctx, uint8_t sensnum)
{
    std::string connection;
    std::string path;

    if (sensnum == reservedSensorNumber)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    auto status = getSensorConnection(ctx, sensnum, connection, path);
    if (status)
    {
        return ipmi::response(status);
    }

#ifdef FEATURE_HYBRID_SENSORS
    if (auto sensor = findStaticSensor(path);
        sensor != ipmi::sensor::sensors.end() &&
        getSensorEventTypeFromPath(path) !=
            static_cast<uint8_t>(SensorEventTypeCodes::threshold))
    {
        if (ipmi::sensor::Mutability::Read !=
            (sensor->second.mutability & ipmi::sensor::Mutability::Read))
        {
            return ipmi::responseIllegalCommand();
        }

        uint8_t operation;
        try
        {
            ipmi::sensor::GetSensorResponse getResponse =
                sensor->second.getFunc(sensor->second);

            if (getResponse.readingOrStateUnavailable)
            {
                operation |= static_cast<uint8_t>(
                    IPMISensorReadingByte2::readingStateUnavailable);
            }
            if (getResponse.scanningEnabled)
            {
                operation |= static_cast<uint8_t>(
                    IPMISensorReadingByte2::sensorScanningEnable);
            }
            if (getResponse.allEventMessagesEnabled)
            {
                operation |= static_cast<uint8_t>(
                    IPMISensorReadingByte2::eventMessagesEnable);
            }
            return ipmi::responseSuccess(
                getResponse.reading, operation,
                getResponse.thresholdLevelsStates,
                getResponse.discreteReadingSensorStates);
        }
        catch (const std::exception& e)
        {
            operation |= static_cast<uint8_t>(
                IPMISensorReadingByte2::readingStateUnavailable);
            return ipmi::responseSuccess(0, operation, 0, std::nullopt);
        }
    }
#endif

    DbusInterfaceMap sensorMap;
    if (!getSensorMap(ctx, connection, path, sensorMap))
    {
        return ipmi::responseResponseError();
    }
    auto sensorObject = sensorMap.find(sensor::sensorInterface);

    if (sensorObject == sensorMap.end() ||
        sensorObject->second.find("Value") == sensorObject->second.end())
    {
        return ipmi::responseResponseError();
    }
    auto& valueVariant = sensorObject->second["Value"];
    double reading = std::visit(VariantToDoubleVisitor(), valueVariant);

    double max = 0;
    double min = 0;
    getSensorMaxMin(sensorMap, max, min);

    int16_t mValue = 0;
    int16_t bValue = 0;
    int8_t rExp = 0;
    int8_t bExp = 0;
    bool bSigned = false;

    if (!getSensorAttributes(max, min, mValue, rExp, bValue, bExp, bSigned))
    {
        return ipmi::responseResponseError();
    }

    uint8_t value =
        scaleIPMIValueFromDouble(reading, mValue, rExp, bValue, bExp, bSigned);
    uint8_t operation =
        static_cast<uint8_t>(IPMISensorReadingByte2::sensorScanningEnable);
    operation |=
        static_cast<uint8_t>(IPMISensorReadingByte2::eventMessagesEnable);
    bool notReading = std::isnan(reading);

    if (!notReading)
    {
        auto availableObject =
            sensorMap.find("xyz.openbmc_project.State.Decorator.Availability");
        if (availableObject != sensorMap.end())
        {
            auto findAvailable = availableObject->second.find("Available");
            if (findAvailable != availableObject->second.end())
            {
                bool* available = std::get_if<bool>(&(findAvailable->second));
                if (available && !(*available))
                {
                    notReading = true;
                }
            }
        }
    }

    if (notReading)
    {
        operation |= static_cast<uint8_t>(
            IPMISensorReadingByte2::readingStateUnavailable);
    }

    if constexpr (details::enableInstrumentation)
    {
        int byteValue;
        if (bSigned)
        {
            byteValue = static_cast<int>(static_cast<int8_t>(value));
        }
        else
        {
            byteValue = static_cast<int>(static_cast<uint8_t>(value));
        }

        // Keep stats on the reading just obtained, even if it is "NaN"
        if (details::sdrStatsTable.updateReading((ctx->lun << 8) | sensnum,
                                                 reading, byteValue))
        {
            // This is the first reading, show the coefficients
            double step = (max - min) / 255.0;
            std::cerr
                << "IPMI sensor "
                << details::sdrStatsTable.getName((ctx->lun << 8) | sensnum)
                << ": Range min=" << min << " max=" << max << ", step=" << step
                << ", Coefficients mValue=" << static_cast<int>(mValue)
                << " rExp=" << static_cast<int>(rExp)
                << " bValue=" << static_cast<int>(bValue)
                << " bExp=" << static_cast<int>(bExp)
                << " bSigned=" << static_cast<int>(bSigned) << "\n";
        }
    }

    uint8_t thresholds = 0;

    auto warningObject =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Warning");
    if (warningObject != sensorMap.end())
    {
        auto alarmHigh = warningObject->second.find("WarningAlarmHigh");
        auto alarmLow = warningObject->second.find("WarningAlarmLow");
        if (alarmHigh != warningObject->second.end())
        {
            if (std::get<bool>(alarmHigh->second))
            {
                thresholds |= static_cast<uint8_t>(
                    IPMISensorReadingByte3::upperNonCritical);
            }
        }
        if (alarmLow != warningObject->second.end())
        {
            if (std::get<bool>(alarmLow->second))
            {
                thresholds |= static_cast<uint8_t>(
                    IPMISensorReadingByte3::lowerNonCritical);
            }
        }
    }

    auto criticalObject =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Critical");
    if (criticalObject != sensorMap.end())
    {
        auto alarmHigh = criticalObject->second.find("CriticalAlarmHigh");
        auto alarmLow = criticalObject->second.find("CriticalAlarmLow");
        if (alarmHigh != criticalObject->second.end())
        {
            if (std::get<bool>(alarmHigh->second))
            {
                thresholds |=
                    static_cast<uint8_t>(IPMISensorReadingByte3::upperCritical);
            }
        }
        if (alarmLow != criticalObject->second.end())
        {
            if (std::get<bool>(alarmLow->second))
            {
                thresholds |=
                    static_cast<uint8_t>(IPMISensorReadingByte3::lowerCritical);
            }
        }
    }

    // no discrete as of today so optional byte is never returned
    return ipmi::responseSuccess(value, operation, thresholds, std::nullopt);
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
    ipmi::Context::ptr ctx, uint8_t sensorNum, bool lowerNonCriticalThreshMask,
    bool lowerCriticalThreshMask, bool lowerNonRecovThreshMask,
    bool upperNonCriticalThreshMask, bool upperCriticalThreshMask,
    bool upperNonRecovThreshMask, uint2_t reserved, uint8_t lowerNonCritical,
    uint8_t lowerCritical, [[maybe_unused]] uint8_t lowerNonRecoverable,
    uint8_t upperNonCritical, uint8_t upperCritical,
    [[maybe_unused]] uint8_t upperNonRecoverable)
{
    if (sensorNum == reservedSensorNumber || reserved)
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

    std::string connection;
    std::string path;

    ipmi::Cc status = getSensorConnection(ctx, sensorNum, connection, path);
    if (status)
    {
        return ipmi::response(status);
    }
    DbusInterfaceMap sensorMap;
    if (!getSensorMap(ctx, connection, path, sensorMap))
    {
        return ipmi::responseResponseError();
    }

    double max = 0;
    double min = 0;
    getSensorMaxMin(sensorMap, max, min);

    int16_t mValue = 0;
    int16_t bValue = 0;
    int8_t rExp = 0;
    int8_t bExp = 0;
    bool bSigned = false;

    if (!getSensorAttributes(max, min, mValue, rExp, bValue, bExp, bSigned))
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
        auto findThreshold =
            sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Critical");
        if (findThreshold == sensorMap.end())
        {
            return ipmi::responseInvalidFieldRequest();
        }
        if (lowerCriticalThreshMask)
        {
            auto findLower = findThreshold->second.find("CriticalLow");
            if (findLower == findThreshold->second.end())
            {
                return ipmi::responseInvalidFieldRequest();
            }
            thresholdsToSet.emplace_back("CriticalLow", lowerCritical,
                                         findThreshold->first);
        }
        if (upperCriticalThreshMask)
        {
            auto findUpper = findThreshold->second.find("CriticalHigh");
            if (findUpper == findThreshold->second.end())
            {
                return ipmi::responseInvalidFieldRequest();
            }
            thresholdsToSet.emplace_back("CriticalHigh", upperCritical,
                                         findThreshold->first);
        }
    }
    if (lowerNonCriticalThreshMask || upperNonCriticalThreshMask)
    {
        auto findThreshold =
            sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Warning");
        if (findThreshold == sensorMap.end())
        {
            return ipmi::responseInvalidFieldRequest();
        }
        if (lowerNonCriticalThreshMask)
        {
            auto findLower = findThreshold->second.find("WarningLow");
            if (findLower == findThreshold->second.end())
            {
                return ipmi::responseInvalidFieldRequest();
            }
            thresholdsToSet.emplace_back("WarningLow", lowerNonCritical,
                                         findThreshold->first);
        }
        if (upperNonCriticalThreshMask)
        {
            auto findUpper = findThreshold->second.find("WarningHigh");
            if (findUpper == findThreshold->second.end())
            {
                return ipmi::responseInvalidFieldRequest();
            }
            thresholdsToSet.emplace_back("WarningHigh", upperNonCritical,
                                         findThreshold->first);
        }
    }
    for (const auto& property : thresholdsToSet)
    {
        // from section 36.3 in the IPMI Spec, assume all linear
        double valueToSet = ((mValue * std::get<thresholdValue>(property)) +
                             (bValue * std::pow(10.0, bExp))) *
                            std::pow(10.0, rExp);
        setDbusProperty(
            *getSdBus(), connection, path, std::get<interface>(property),
            std::get<propertyName>(property), ipmi::Value(valueToSet));
    }
    return ipmi::responseSuccess();
}

IPMIThresholds getIPMIThresholds(const DbusInterfaceMap& sensorMap)
{
    IPMIThresholds resp;
    auto warningInterface =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Warning");
    auto criticalInterface =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Critical");

    if ((warningInterface != sensorMap.end()) ||
        (criticalInterface != sensorMap.end()))
    {
        auto sensorPair = sensorMap.find(sensor::sensorInterface);

        if (sensorPair == sensorMap.end())
        {
            // should not have been able to find a sensor not implementing
            // the sensor object
            throw std::runtime_error("Invalid sensor map");
        }

        double max = 0;
        double min = 0;
        getSensorMaxMin(sensorMap, max, min);

        int16_t mValue = 0;
        int16_t bValue = 0;
        int8_t rExp = 0;
        int8_t bExp = 0;
        bool bSigned = false;

        if (!getSensorAttributes(max, min, mValue, rExp, bValue, bExp, bSigned))
        {
            throw std::runtime_error("Invalid sensor atrributes");
        }
        if (warningInterface != sensorMap.end())
        {
            auto& warningMap = warningInterface->second;

            auto warningHigh = warningMap.find("WarningHigh");
            auto warningLow = warningMap.find("WarningLow");

            if (warningHigh != warningMap.end())
            {
                double value =
                    std::visit(VariantToDoubleVisitor(), warningHigh->second);
                if (std::isfinite(value))
                {
                    resp.warningHigh = scaleIPMIValueFromDouble(
                        value, mValue, rExp, bValue, bExp, bSigned);
                }
            }
            if (warningLow != warningMap.end())
            {
                double value =
                    std::visit(VariantToDoubleVisitor(), warningLow->second);
                if (std::isfinite(value))
                {
                    resp.warningLow = scaleIPMIValueFromDouble(
                        value, mValue, rExp, bValue, bExp, bSigned);
                }
            }
        }
        if (criticalInterface != sensorMap.end())
        {
            auto& criticalMap = criticalInterface->second;

            auto criticalHigh = criticalMap.find("CriticalHigh");
            auto criticalLow = criticalMap.find("CriticalLow");

            if (criticalHigh != criticalMap.end())
            {
                double value =
                    std::visit(VariantToDoubleVisitor(), criticalHigh->second);
                if (std::isfinite(value))
                {
                    resp.criticalHigh = scaleIPMIValueFromDouble(
                        value, mValue, rExp, bValue, bExp, bSigned);
                }
            }
            if (criticalLow != criticalMap.end())
            {
                double value =
                    std::visit(VariantToDoubleVisitor(), criticalLow->second);
                if (std::isfinite(value))
                {
                    resp.criticalLow = scaleIPMIValueFromDouble(
                        value, mValue, rExp, bValue, bExp, bSigned);
                }
            }
        }
    }
    return resp;
}

ipmi::RspType<uint8_t, // readable
              uint8_t, // lowerNCrit
              uint8_t, // lowerCrit
              uint8_t, // lowerNrecoverable
              uint8_t, // upperNC
              uint8_t, // upperCrit
              uint8_t> // upperNRecoverable
    ipmiSenGetSensorThresholds(ipmi::Context::ptr ctx, uint8_t sensorNumber)
{
    std::string connection;
    std::string path;

    if (sensorNumber == reservedSensorNumber)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    auto status = getSensorConnection(ctx, sensorNumber, connection, path);
    if (status)
    {
        return ipmi::response(status);
    }

    DbusInterfaceMap sensorMap;
    if (!getSensorMap(ctx, connection, path, sensorMap))
    {
        return ipmi::responseResponseError();
    }

    IPMIThresholds thresholdData;
    try
    {
        thresholdData = getIPMIThresholds(sensorMap);
    }
    catch (const std::exception&)
    {
        return ipmi::responseResponseError();
    }

    uint8_t readable = 0;
    uint8_t lowerNC = 0;
    uint8_t lowerCritical = 0;
    uint8_t lowerNonRecoverable = 0;
    uint8_t upperNC = 0;
    uint8_t upperCritical = 0;
    uint8_t upperNonRecoverable = 0;

    if (thresholdData.warningHigh)
    {
        readable |=
            1 << static_cast<uint8_t>(IPMIThresholdRespBits::upperNonCritical);
        upperNC = *thresholdData.warningHigh;
    }
    if (thresholdData.warningLow)
    {
        readable |=
            1 << static_cast<uint8_t>(IPMIThresholdRespBits::lowerNonCritical);
        lowerNC = *thresholdData.warningLow;
    }

    if (thresholdData.criticalHigh)
    {
        readable |=
            1 << static_cast<uint8_t>(IPMIThresholdRespBits::upperCritical);
        upperCritical = *thresholdData.criticalHigh;
    }
    if (thresholdData.criticalLow)
    {
        readable |=
            1 << static_cast<uint8_t>(IPMIThresholdRespBits::lowerCritical);
        lowerCritical = *thresholdData.criticalLow;
    }

    return ipmi::responseSuccess(readable, lowerNC, lowerCritical,
                                 lowerNonRecoverable, upperNC, upperCritical,
                                 upperNonRecoverable);
}

/** @brief implements the get Sensor event enable command
 *  @param sensorNumber - sensor number
 *
 *  @returns IPMI completion code plus response data
 *   - enabled               - Sensor Event messages
 *   - assertionEnabledLsb   - Assertion event messages
 *   - assertionEnabledMsb   - Assertion event messages
 *   - deassertionEnabledLsb - Deassertion event messages
 *   - deassertionEnabledMsb - Deassertion event messages
 */

ipmi::RspType<uint8_t, // enabled
              uint8_t, // assertionEnabledLsb
              uint8_t, // assertionEnabledMsb
              uint8_t, // deassertionEnabledLsb
              uint8_t> // deassertionEnabledMsb
    ipmiSenGetSensorEventEnable(ipmi::Context::ptr ctx, uint8_t sensorNum)
{
    std::string connection;
    std::string path;

    uint8_t enabled = 0;
    uint8_t assertionEnabledLsb = 0;
    uint8_t assertionEnabledMsb = 0;
    uint8_t deassertionEnabledLsb = 0;
    uint8_t deassertionEnabledMsb = 0;

    if (sensorNum == reservedSensorNumber)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    auto status = getSensorConnection(ctx, sensorNum, connection, path);
    if (status)
    {
        return ipmi::response(status);
    }

#ifdef FEATURE_HYBRID_SENSORS
    if (auto sensor = findStaticSensor(path);
        sensor != ipmi::sensor::sensors.end() &&
        getSensorEventTypeFromPath(path) !=
            static_cast<uint8_t>(SensorEventTypeCodes::threshold))
    {
        enabled = static_cast<uint8_t>(
            IPMISensorEventEnableByte2::sensorScanningEnable);
        uint16_t assertionEnabled = 0;
        for (auto& offsetValMap : sensor->second.propertyInterfaces.begin()
                                      ->second.begin()
                                      ->second.second)
        {
            assertionEnabled |= (1 << offsetValMap.first);
        }
        assertionEnabledLsb = static_cast<uint8_t>((assertionEnabled & 0xFF));
        assertionEnabledMsb =
            static_cast<uint8_t>(((assertionEnabled >> 8) & 0xFF));

        return ipmi::responseSuccess(enabled, assertionEnabledLsb,
                                     assertionEnabledMsb, deassertionEnabledLsb,
                                     deassertionEnabledMsb);
    }
#endif

    DbusInterfaceMap sensorMap;
    if (!getSensorMap(ctx, connection, path, sensorMap))
    {
        return ipmi::responseResponseError();
    }

    auto warningInterface =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Warning");
    auto criticalInterface =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Critical");
    if ((warningInterface != sensorMap.end()) ||
        (criticalInterface != sensorMap.end()))
    {
        enabled = static_cast<uint8_t>(
            IPMISensorEventEnableByte2::sensorScanningEnable);
        if (warningInterface != sensorMap.end())
        {
            auto& warningMap = warningInterface->second;

            auto warningHigh = warningMap.find("WarningHigh");
            auto warningLow = warningMap.find("WarningLow");
            if (warningHigh != warningMap.end())
            {
                double value =
                    std::visit(VariantToDoubleVisitor(), warningHigh->second);
                if (std::isfinite(value))
                {
                    assertionEnabledLsb |= static_cast<uint8_t>(
                        IPMISensorEventEnableThresholds::
                            upperNonCriticalGoingHigh);
                    deassertionEnabledLsb |= static_cast<uint8_t>(
                        IPMISensorEventEnableThresholds::
                            upperNonCriticalGoingLow);
                }
            }
            if (warningLow != warningMap.end())
            {
                double value =
                    std::visit(VariantToDoubleVisitor(), warningLow->second);
                if (std::isfinite(value))
                {
                    assertionEnabledLsb |= static_cast<uint8_t>(
                        IPMISensorEventEnableThresholds::
                            lowerNonCriticalGoingLow);
                    deassertionEnabledLsb |= static_cast<uint8_t>(
                        IPMISensorEventEnableThresholds::
                            lowerNonCriticalGoingHigh);
                }
            }
        }
        if (criticalInterface != sensorMap.end())
        {
            auto& criticalMap = criticalInterface->second;

            auto criticalHigh = criticalMap.find("CriticalHigh");
            auto criticalLow = criticalMap.find("CriticalLow");

            if (criticalHigh != criticalMap.end())
            {
                double value =
                    std::visit(VariantToDoubleVisitor(), criticalHigh->second);
                if (std::isfinite(value))
                {
                    assertionEnabledMsb |= static_cast<uint8_t>(
                        IPMISensorEventEnableThresholds::
                            upperCriticalGoingHigh);
                    deassertionEnabledMsb |= static_cast<uint8_t>(
                        IPMISensorEventEnableThresholds::upperCriticalGoingLow);
                }
            }
            if (criticalLow != criticalMap.end())
            {
                double value =
                    std::visit(VariantToDoubleVisitor(), criticalLow->second);
                if (std::isfinite(value))
                {
                    assertionEnabledLsb |= static_cast<uint8_t>(
                        IPMISensorEventEnableThresholds::lowerCriticalGoingLow);
                    deassertionEnabledLsb |= static_cast<uint8_t>(
                        IPMISensorEventEnableThresholds::
                            lowerCriticalGoingHigh);
                }
            }
        }
    }

    return ipmi::responseSuccess(enabled, assertionEnabledLsb,
                                 assertionEnabledMsb, deassertionEnabledLsb,
                                 deassertionEnabledMsb);
}

/** @brief implements the get Sensor event status command
 *  @param sensorNumber - sensor number, FFh = reserved
 *
 *  @returns IPMI completion code plus response data
 *   - sensorEventStatus - Sensor Event messages state
 *   - assertions        - Assertion event messages
 *   - deassertions      - Deassertion event messages
 */
ipmi::RspType<uint8_t,         // sensorEventStatus
              std::bitset<16>, // assertions
              std::bitset<16>  // deassertion
              >
    ipmiSenGetSensorEventStatus(ipmi::Context::ptr ctx, uint8_t sensorNum)
{
    if (sensorNum == reservedSensorNumber)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    std::string connection;
    std::string path;
    auto status = getSensorConnection(ctx, sensorNum, connection, path);
    if (status)
    {
        lg2::error("ipmiSenGetSensorEventStatus: Sensor connection Error, "
                   "sensor number: {SENSOR_NUM}",
                   "SENSOR_NUM", sensorNum);
        return ipmi::response(status);
    }

#ifdef FEATURE_HYBRID_SENSORS
    if (auto sensor = findStaticSensor(path);
        sensor != ipmi::sensor::sensors.end() &&
        getSensorEventTypeFromPath(path) !=
            static_cast<uint8_t>(SensorEventTypeCodes::threshold))
    {
        auto response = ipmi::sensor::get::mapDbusToAssertion(
            sensor->second, path, sensor->second.sensorInterface);
        std::bitset<16> assertions;
        // deassertions are not used.
        std::bitset<16> deassertions = 0;
        uint8_t sensorEventStatus;
        if (response.readingOrStateUnavailable)
        {
            sensorEventStatus |= static_cast<uint8_t>(
                IPMISensorReadingByte2::readingStateUnavailable);
        }
        if (response.scanningEnabled)
        {
            sensorEventStatus |= static_cast<uint8_t>(
                IPMISensorReadingByte2::sensorScanningEnable);
        }
        if (response.allEventMessagesEnabled)
        {
            sensorEventStatus |= static_cast<uint8_t>(
                IPMISensorReadingByte2::eventMessagesEnable);
        }
        assertions |= response.discreteReadingSensorStates << 8;
        assertions |= response.thresholdLevelsStates;
        return ipmi::responseSuccess(sensorEventStatus, assertions,
                                     deassertions);
    }
#endif

    DbusInterfaceMap sensorMap;
    if (!getSensorMap(ctx, connection, path, sensorMap))
    {
        lg2::error("ipmiSenGetSensorEventStatus: Sensor Mapping Error, "
                   "sensor path: {SENSOR_PATH}",
                   "SENSOR_PATH", path);
        return ipmi::responseResponseError();
    }

    uint8_t sensorEventStatus =
        static_cast<uint8_t>(IPMISensorEventEnableByte2::sensorScanningEnable);
    std::bitset<16> assertions = 0;
    std::bitset<16> deassertions = 0;

    // handle VR typed sensor
    auto vrInterface = sensorMap.find(sensor::vrInterface);
    if (vrInterface != sensorMap.end())
    {
        if (!sensor::getVrEventStatus(ctx, connection, path,
                                      vrInterface->second, assertions))
        {
            return ipmi::responseResponseError();
        }

        // both Event Message and Sensor Scanning are disable for VR.
        sensorEventStatus = 0;
        return ipmi::responseSuccess(sensorEventStatus, assertions,
                                     deassertions);
    }

    auto warningInterface =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Warning");
    auto criticalInterface =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Critical");

    std::optional<bool> criticalDeassertHigh =
        thresholdDeassertMap[path]["CriticalAlarmHigh"];
    std::optional<bool> criticalDeassertLow =
        thresholdDeassertMap[path]["CriticalAlarmLow"];
    std::optional<bool> warningDeassertHigh =
        thresholdDeassertMap[path]["WarningAlarmHigh"];
    std::optional<bool> warningDeassertLow =
        thresholdDeassertMap[path]["WarningAlarmLow"];

    if (criticalDeassertHigh && !*criticalDeassertHigh)
    {
        deassertions.set(static_cast<size_t>(
            IPMIGetSensorEventEnableThresholds::upperCriticalGoingHigh));
    }
    if (criticalDeassertLow && !*criticalDeassertLow)
    {
        deassertions.set(static_cast<size_t>(
            IPMIGetSensorEventEnableThresholds::upperCriticalGoingLow));
    }
    if (warningDeassertHigh && !*warningDeassertHigh)
    {
        deassertions.set(static_cast<size_t>(
            IPMIGetSensorEventEnableThresholds::upperNonCriticalGoingHigh));
    }
    if (warningDeassertLow && !*warningDeassertLow)
    {
        deassertions.set(static_cast<size_t>(
            IPMIGetSensorEventEnableThresholds::lowerNonCriticalGoingHigh));
    }
    if ((warningInterface != sensorMap.end()) ||
        (criticalInterface != sensorMap.end()))
    {
        sensorEventStatus = static_cast<size_t>(
            IPMISensorEventEnableByte2::eventMessagesEnable);
        if (warningInterface != sensorMap.end())
        {
            auto& warningMap = warningInterface->second;

            auto warningHigh = warningMap.find("WarningAlarmHigh");
            auto warningLow = warningMap.find("WarningAlarmLow");
            auto warningHighAlarm = false;
            auto warningLowAlarm = false;

            if (warningHigh != warningMap.end())
            {
                warningHighAlarm = std::get<bool>(warningHigh->second);
            }
            if (warningLow != warningMap.end())
            {
                warningLowAlarm = std::get<bool>(warningLow->second);
            }
            if (warningHighAlarm)
            {
                assertions.set(static_cast<size_t>(
                    IPMIGetSensorEventEnableThresholds::
                        upperNonCriticalGoingHigh));
            }
            if (warningLowAlarm)
            {
                assertions.set(static_cast<size_t>(
                    IPMIGetSensorEventEnableThresholds::
                        lowerNonCriticalGoingLow));
            }
        }
        if (criticalInterface != sensorMap.end())
        {
            auto& criticalMap = criticalInterface->second;

            auto criticalHigh = criticalMap.find("CriticalAlarmHigh");
            auto criticalLow = criticalMap.find("CriticalAlarmLow");
            auto criticalHighAlarm = false;
            auto criticalLowAlarm = false;

            if (criticalHigh != criticalMap.end())
            {
                criticalHighAlarm = std::get<bool>(criticalHigh->second);
            }
            if (criticalLow != criticalMap.end())
            {
                criticalLowAlarm = std::get<bool>(criticalLow->second);
            }
            if (criticalHighAlarm)
            {
                assertions.set(static_cast<size_t>(
                    IPMIGetSensorEventEnableThresholds::
                        upperCriticalGoingHigh));
            }
            if (criticalLowAlarm)
            {
                assertions.set(static_cast<size_t>(
                    IPMIGetSensorEventEnableThresholds::lowerCriticalGoingLow));
            }
        }
    }

    return ipmi::responseSuccess(sensorEventStatus, assertions, deassertions);
}

// Construct a type 1 SDR for threshold sensor.
void constructSensorSdrHeaderKey(uint16_t sensorNum, uint16_t recordID,
                                 get_sdr::SensorDataFullRecord& record)
{
    get_sdr::header::set_record_id(
        recordID, reinterpret_cast<get_sdr::SensorDataRecordHeader*>(&record));

    uint8_t sensornumber = static_cast<uint8_t>(sensorNum);
    uint8_t lun = static_cast<uint8_t>(sensorNum >> 8);

    record.header.sdr_version = ipmiSdrVersion;
    record.header.record_type = get_sdr::SENSOR_DATA_FULL_RECORD;
    record.header.record_length = sizeof(get_sdr::SensorDataFullRecord) -
                                  sizeof(get_sdr::SensorDataRecordHeader);
    record.key.owner_id = bmcI2CAddr;
    record.key.owner_lun = lun;
    record.key.sensor_number = sensornumber;
}
bool constructSensorSdr(
    ipmi::Context::ptr ctx,
    const std::unordered_set<std::string>& ipmiDecoratorPaths,
    uint16_t sensorNum, uint16_t recordID, const std::string& service,
    const std::string& path, get_sdr::SensorDataFullRecord& record)
{
    constructSensorSdrHeaderKey(sensorNum, recordID, record);

    DbusInterfaceMap sensorMap;
    if (!getSensorMap(ctx, service, path, sensorMap, sensorMapSdrUpdatePeriod))
    {
        lg2::error("Failed to update sensor map for threshold sensor, "
                   "service: {SERVICE}, path: {PATH}",
                   "SERVICE", service, "PATH", path);
        return false;
    }

    record.body.sensor_capabilities = 0x68; // auto rearm - todo hysteresis
    record.body.sensor_type = getSensorTypeFromPath(path);
    std::string type = getSensorTypeStringFromPath(path);
    auto typeCstr = type.c_str();
    auto findUnits = sensorUnits.find(typeCstr);
    if (findUnits != sensorUnits.end())
    {
        record.body.sensor_units_2_base =
            static_cast<uint8_t>(findUnits->second);
    } // else default 0x0 unspecified

    record.body.event_reading_type = getSensorEventTypeFromPath(path);

    auto sensorObject = sensorMap.find(sensor::sensorInterface);
    if (sensorObject == sensorMap.end())
    {
        lg2::error("constructSensorSdr: sensorObject error");
        return false;
    }

    uint8_t entityId = 0;
    uint8_t entityInstance = 0x01;

    // follow the association chain to get the parent board's entityid and
    // entityInstance
    updateIpmiFromAssociation(path, ipmiDecoratorPaths, sensorMap, entityId,
                              entityInstance);

    record.body.entity_id = entityId;
    record.body.entity_instance = entityInstance;

    double max = 0;
    double min = 0;
    getSensorMaxMin(sensorMap, max, min);

    int16_t mValue = 0;
    int8_t rExp = 0;
    int16_t bValue = 0;
    int8_t bExp = 0;
    bool bSigned = false;

    if (!getSensorAttributes(max, min, mValue, rExp, bValue, bExp, bSigned))
    {
        lg2::error("constructSensorSdr: getSensorAttributes error");
        return false;
    }

    // The record.body is a struct SensorDataFullRecordBody
    // from sensorhandler.hpp in phosphor-ipmi-host.
    // The meaning of these bits appears to come from
    // table 43.1 of the IPMI spec.
    // The above 5 sensor attributes are stuffed in as follows:
    // Byte 21 = AA000000 = analog interpretation, 10 signed, 00 unsigned
    // Byte 22-24 are for other purposes
    // Byte 25 = MMMMMMMM = LSB of M
    // Byte 26 = MMTTTTTT = MSB of M (signed), and Tolerance
    // Byte 27 = BBBBBBBB = LSB of B
    // Byte 28 = BBAAAAAA = MSB of B (signed), and LSB of Accuracy
    // Byte 29 = AAAAEE00 = MSB of Accuracy, exponent of Accuracy
    // Byte 30 = RRRRBBBB = rExp (signed), bExp (signed)

    // apply M, B, and exponents, M and B are 10 bit values, exponents are 4
    record.body.m_lsb = mValue & 0xFF;

    uint8_t mBitSign = (mValue < 0) ? 1 : 0;
    uint8_t mBitNine = (mValue & 0x0100) >> 8;

    // move the smallest bit of the MSB into place (bit 9)
    // the MSbs are bits 7:8 in m_msb_and_tolerance
    record.body.m_msb_and_tolerance = (mBitSign << 7) | (mBitNine << 6);

    record.body.b_lsb = bValue & 0xFF;

    uint8_t bBitSign = (bValue < 0) ? 1 : 0;
    uint8_t bBitNine = (bValue & 0x0100) >> 8;

    // move the smallest bit of the MSB into place (bit 9)
    // the MSbs are bits 7:8 in b_msb_and_accuracy_lsb
    record.body.b_msb_and_accuracy_lsb = (bBitSign << 7) | (bBitNine << 6);

    uint8_t rExpSign = (rExp < 0) ? 1 : 0;
    uint8_t rExpBits = rExp & 0x07;

    uint8_t bExpSign = (bExp < 0) ? 1 : 0;
    uint8_t bExpBits = bExp & 0x07;

    // move rExp and bExp into place
    record.body.r_b_exponents =
        (rExpSign << 7) | (rExpBits << 4) | (bExpSign << 3) | bExpBits;

    // Set the analog reading byte interpretation accordingly
    record.body.sensor_units_1 = (bSigned ? 1 : 0) << 7;

    // TODO(): Perhaps care about Tolerance, Accuracy, and so on
    // These seem redundant, but derivable from the above 5 attributes
    // Original comment said "todo fill out rest of units"

    // populate sensor name from path
    auto name = sensor::parseSdrIdFromPath(path);
    get_sdr::body::set_id_strlen(name.size(), &record.body);
    get_sdr::body::set_id_type(3, &record.body); // "8-bit ASCII + Latin 1"
    std::memcpy(record.body.id_string, name.c_str(),
                std::min(name.length() + 1, sizeof(record.body.id_string)));

    // Remember the sensor name, as determined for this sensor number
    details::sdrStatsTable.updateName(sensorNum, name);

    bool sensorSettable = false;
    auto mutability =
        sensorMap.find("xyz.openbmc_project.Sensor.ValueMutability");
    if (mutability != sensorMap.end())
    {
        sensorSettable =
            mappedVariant<bool>(mutability->second, "Mutable", false);
    }
    get_sdr::body::init_settable_state(sensorSettable, &record.body);

    // Grant write permission to sensors deemed externally settable
    details::sdrWriteTable.setWritePermission(sensorNum, sensorSettable);

    IPMIThresholds thresholdData;
    try
    {
        thresholdData = getIPMIThresholds(sensorMap);
    }
    catch (const std::exception&)
    {
        lg2::error("constructSensorSdr: getIPMIThresholds error");
        return false;
    }

    if (thresholdData.criticalHigh)
    {
        record.body.upper_critical_threshold = *thresholdData.criticalHigh;
        record.body.supported_deassertions[1] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::criticalThreshold);
        record.body.supported_deassertions[1] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::upperCriticalGoingHigh);
        record.body.supported_assertions[1] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::upperCriticalGoingHigh);
        record.body.discrete_reading_setting_mask[0] |=
            static_cast<uint8_t>(IPMISensorReadingByte3::upperCritical);
    }
    if (thresholdData.warningHigh)
    {
        record.body.upper_noncritical_threshold = *thresholdData.warningHigh;
        record.body.supported_deassertions[1] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::nonCriticalThreshold);
        record.body.supported_deassertions[0] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::upperNonCriticalGoingHigh);
        record.body.supported_assertions[0] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::upperNonCriticalGoingHigh);
        record.body.discrete_reading_setting_mask[0] |=
            static_cast<uint8_t>(IPMISensorReadingByte3::upperNonCritical);
    }
    if (thresholdData.criticalLow)
    {
        record.body.lower_critical_threshold = *thresholdData.criticalLow;
        record.body.supported_assertions[1] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::criticalThreshold);
        record.body.supported_deassertions[0] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::lowerCriticalGoingLow);
        record.body.supported_assertions[0] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::lowerCriticalGoingLow);
        record.body.discrete_reading_setting_mask[0] |=
            static_cast<uint8_t>(IPMISensorReadingByte3::lowerCritical);
    }
    if (thresholdData.warningLow)
    {
        record.body.lower_noncritical_threshold = *thresholdData.warningLow;
        record.body.supported_assertions[1] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::nonCriticalThreshold);
        record.body.supported_deassertions[0] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::lowerNonCriticalGoingLow);
        record.body.supported_assertions[0] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::lowerNonCriticalGoingLow);
        record.body.discrete_reading_setting_mask[0] |=
            static_cast<uint8_t>(IPMISensorReadingByte3::lowerNonCritical);
    }

    // everything that is readable is setable
    record.body.discrete_reading_setting_mask[1] =
        record.body.discrete_reading_setting_mask[0];
    return true;
}

#ifdef FEATURE_HYBRID_SENSORS
// Construct a type 1 SDR for discrete Sensor typed sensor.
void constructStaticSensorSdr(ipmi::Context::ptr, uint16_t sensorNum,
                              uint16_t recordID,
                              ipmi::sensor::IdInfoMap::const_iterator sensor,
                              get_sdr::SensorDataFullRecord& record)
{
    constructSensorSdrHeaderKey(sensorNum, recordID, record);

    record.body.entity_id = sensor->second.entityType;
    record.body.sensor_type = sensor->second.sensorType;
    record.body.event_reading_type = sensor->second.sensorReadingType;
    record.body.entity_instance = sensor->second.instance;
    if (ipmi::sensor::Mutability::Write ==
        (sensor->second.mutability & ipmi::sensor::Mutability::Write))
    {
        get_sdr::body::init_settable_state(true, &(record.body));
    }

    auto id_string = sensor->second.sensorName;

    if (id_string.empty())
    {
        id_string = sensor->second.sensorNameFunc(sensor->second);
    }

    if (id_string.length() > FULL_RECORD_ID_STR_MAX_LENGTH)
    {
        get_sdr::body::set_id_strlen(FULL_RECORD_ID_STR_MAX_LENGTH,
                                     &(record.body));
    }
    else
    {
        get_sdr::body::set_id_strlen(id_string.length(), &(record.body));
    }
    get_sdr::body::set_id_type(3, &record.body); // "8-bit ASCII + Latin 1"
    std::strncpy(record.body.id_string, id_string.c_str(),
                 get_sdr::body::get_id_strlen(&(record.body)));
}
#endif

// Construct type 3 SDR header and key (for VR and other discrete sensors)
void constructEventSdrHeaderKey(uint16_t sensorNum, uint16_t recordID,
                                get_sdr::SensorDataEventRecord& record)
{
    uint8_t sensornumber = static_cast<uint8_t>(sensorNum);
    uint8_t lun = static_cast<uint8_t>(sensorNum >> 8);

    get_sdr::header::set_record_id(
        recordID, reinterpret_cast<get_sdr::SensorDataRecordHeader*>(&record));

    record.header.sdr_version = ipmiSdrVersion;
    record.header.record_type = get_sdr::SENSOR_DATA_EVENT_RECORD;
    record.header.record_length = sizeof(get_sdr::SensorDataEventRecord) -
                                  sizeof(get_sdr::SensorDataRecordHeader);
    record.key.owner_id = bmcI2CAddr;
    record.key.owner_lun = lun;
    record.key.sensor_number = sensornumber;

    record.body.entity_id = 0x00;
    record.body.entity_instance = 0x01;
}

// Construct a type 3 SDR for VR typed sensor(daemon).
bool constructVrSdr(ipmi::Context::ptr ctx,
                    const std::unordered_set<std::string>& ipmiDecoratorPaths,
                    uint16_t sensorNum, uint16_t recordID,
                    const std::string& service, const std::string& path,
                    get_sdr::SensorDataEventRecord& record)
{
    constructEventSdrHeaderKey(sensorNum, recordID, record);

    DbusInterfaceMap sensorMap;
    if (!getSensorMap(ctx, service, path, sensorMap, sensorMapSdrUpdatePeriod))
    {
        lg2::error("Failed to update sensor map for VR sensor, "
                   "service: {SERVICE}, path: {PATH}",
                   "SERVICE", service, "PATH", path);
        return false;
    }
    // follow the association chain to get the parent board's entityid and
    // entityInstance
    updateIpmiFromAssociation(path, ipmiDecoratorPaths, sensorMap,
                              record.body.entity_id,
                              record.body.entity_instance);

    // Sensor type is hardcoded as a module/board type instead of parsing from
    // sensor path. This is because VR control is allocated in an independent
    // path(/xyz/openbmc_project/vr/profile/...) which is not categorized by
    // types.
    static constexpr const uint8_t module_board_type = 0x15;
    record.body.sensor_type = module_board_type;
    record.body.event_reading_type = 0x00;

    record.body.sensor_record_sharing_1 = 0x00;
    record.body.sensor_record_sharing_2 = 0x00;

    // populate sensor name from path
    auto name = sensor::parseSdrIdFromPath(path);
    int nameSize = std::min(name.size(), sizeof(record.body.id_string));
    get_sdr::body::set_id_strlen(nameSize, &record.body);
    get_sdr::body::set_id_type(3, &record.body); // "8-bit ASCII + Latin 1"
    std::memset(record.body.id_string, 0x00, sizeof(record.body.id_string));
    std::memcpy(record.body.id_string, name.c_str(), nameSize);

    // Remember the sensor name, as determined for this sensor number
    details::sdrStatsTable.updateName(sensorNum, name);

    return true;
}

uint16_t getNumberOfSensors()
{
    return std::min(getSensorTree().size(), maxIPMISensors);
}

static int getSensorDataRecord(
    ipmi::Context::ptr ctx,
    const std::unordered_set<std::string>& ipmiDecoratorPaths,
    std::vector<uint8_t>& recordData, uint16_t recordID,
    uint8_t readBytes = std::numeric_limits<uint8_t>::max())
{
    recordData.clear();
    size_t lastRecord = ipmi::getNumberOfSensors() +
                        ipmi::sensor::getOtherSensorsCount(ctx) - 1;
    uint16_t nextRecord(recordID + 1);

    if (recordID == lastRecordIndex)
    {
        recordID = lastRecord;
    }
    if (recordID == lastRecord)
    {
        nextRecord = lastRecordIndex;
    }
    if (recordID > lastRecord)
    {
        lg2::error("getSensorDataRecord: recordID > lastRecord error");
        return GENERAL_ERROR;
    }
    if (recordID >= ipmi::getNumberOfSensors())
    {
        if (auto err = ipmi::sensor::getOtherSensorsDataRecord(ctx, recordID,
                                                               recordData);
            err < 0)
        {
            return lastRecordIndex;
        }
        return nextRecord;
    }

    // Perform a incremental scan of the SDR Record ID's and translate the
    // first 765 SDR records (i.e. maxIPMISensors) into IPMI Sensor
    // Numbers. The IPMI sensor numbers are not linear, and have a reserved
    // gap at 0xff. This code creates 254 sensors per LUN, excepting LUN 2
    // which has special meaning.
    std::string connection;
    std::string path;
    std::vector<std::string> interfaces;
    uint16_t sensNumFromRecID{recordID};
    if ((recordID > lun0MaxSensorNum) && (recordID < lun1MaxSensorNum))
    {
        // LUN 0 has one reserved sensor number. Compensate here by adding one
        // to the record ID
        sensNumFromRecID = recordID + 1;
        ctx->lun = lun1;
    }
    else if ((recordID >= lun1MaxSensorNum) && (recordID < maxIPMISensors))
    {
        // LUN 0, 1 have a reserved sensor number. Compensate here by adding 2
        // to the record ID. Skip all 256 sensors in LUN 2, as it has special
        // rules governing its use.
        sensNumFromRecID = recordID + (maxSensorsPerLUN + 1) + 2;
        ctx->lun = lun3;
    }

    auto status =
        getSensorConnection(ctx, static_cast<uint8_t>(sensNumFromRecID),
                            connection, path, &interfaces);
    if (status)
    {
        lg2::error("getSensorDataRecord: getSensorConnection error");
        return GENERAL_ERROR;
    }
    uint16_t sensorNum = getSensorNumberFromPath(path);
    // Return an error on LUN 2 assingments, and any sensor number beyond the
    // range of LUN 3
    if (((sensorNum > lun1MaxSensorNum) && (sensorNum <= maxIPMISensors)) ||
        (sensorNum > lun3MaxSensorNum))
    {
        lg2::error("getSensorDataRecord: invalidSensorNumber");
        return GENERAL_ERROR;
    }
    uint8_t sensornumber = static_cast<uint8_t>(sensorNum);
    uint8_t lun = static_cast<uint8_t>(sensorNum >> 8);

    if ((sensornumber != static_cast<uint8_t>(sensNumFromRecID)) &&
        (lun != ctx->lun))
    {
        lg2::error("getSensorDataRecord: sensor record mismatch");
        return GENERAL_ERROR;
    }

    // Construct full record (SDR type 1) for the threshold sensors
    if (std::find(interfaces.begin(), interfaces.end(),
                  sensor::sensorInterface) != interfaces.end())
    {
        get_sdr::SensorDataFullRecord record = {};

        // If the request doesn't read SDR body, construct only header and key
        // part to avoid additional DBus transaction.
        if (readBytes <= sizeof(record.header) + sizeof(record.key))
        {
            constructSensorSdrHeaderKey(sensorNum, recordID, record);
        }
        else if (!constructSensorSdr(ctx, ipmiDecoratorPaths, sensorNum,
                                     recordID, connection, path, record))
        {
            return GENERAL_ERROR;
        }

        recordData.insert(recordData.end(), reinterpret_cast<uint8_t*>(&record),
                          reinterpret_cast<uint8_t*>(&record) + sizeof(record));

        return nextRecord;
    }

#ifdef FEATURE_HYBRID_SENSORS
    if (auto sensor = findStaticSensor(path);
        sensor != ipmi::sensor::sensors.end() &&
        getSensorEventTypeFromPath(path) !=
            static_cast<uint8_t>(SensorEventTypeCodes::threshold))
    {
        get_sdr::SensorDataFullRecord record = {};

        // If the request doesn't read SDR body, construct only header and key
        // part to avoid additional DBus transaction.
        if (readBytes <= sizeof(record.header) + sizeof(record.key))
        {
            constructSensorSdrHeaderKey(sensorNum, recordID, record);
        }
        else
        {
            constructStaticSensorSdr(ctx, sensorNum, recordID, sensor, record);
        }

        recordData.insert(recordData.end(), reinterpret_cast<uint8_t*>(&record),
                          reinterpret_cast<uint8_t*>(&record) + sizeof(record));

        return nextRecord;
    }
#endif

    // Contruct SDR type 3 record for VR sensor (daemon)
    if (std::find(interfaces.begin(), interfaces.end(), sensor::vrInterface) !=
        interfaces.end())
    {
        get_sdr::SensorDataEventRecord record = {};

        // If the request doesn't read SDR body, construct only header and key
        // part to avoid additional DBus transaction.
        if (readBytes <= sizeof(record.header) + sizeof(record.key))
        {
            constructEventSdrHeaderKey(sensorNum, recordID, record);
        }
        else if (!constructVrSdr(ctx, ipmiDecoratorPaths, sensorNum, recordID,
                                 connection, path, record))
        {
            return GENERAL_ERROR;
        }
        recordData.insert(recordData.end(), reinterpret_cast<uint8_t*>(&record),
                          reinterpret_cast<uint8_t*>(&record) + sizeof(record));
    }

    return nextRecord;
}

/** @brief implements the get SDR Info command
 *  @param operation : 0 or not supplied returns sensor count
 *                     1 return SDR count
 *
 *  @returns IPMI completion code plus response data
 *   - sdrCount - sensor/SDR count
 *   - lunsAndDynamicPopulation - static/Dynamic sensor population flag
 */
static ipmi::RspType<uint8_t, // respcount
                     uint8_t, // dynamic population flags
                     uint32_t // last time a sensor was added
                     >
    ipmiSensorGetDeviceSdrInfo(ipmi::Context::ptr ctx,
                               std::optional<uint8_t> operation)
{
    auto& sensorTree{getSensorTree()};
    uint8_t sdrCount{};
    // Sensors are dynamically allocated
    uint8_t lunsAndDynamicPopulation{0x80};
    constexpr uint8_t getSdrCount{1};
    constexpr uint8_t getSensorCount{0};

    if (!getSensorSubtree(sensorTree) || sensorTree.empty())
    {
        return ipmi::responseResponseError();
    }
    uint16_t numSensors{ipmi::getNumberOfSensors()};
    if (operation.value_or(0) == getSdrCount)
    {
        sdrCount = numSensors + ipmi::sensor::getOtherSensorsCount(ctx) - 1;
    }
    else if (operation.value_or(0) == getSensorCount)
    {
        // Return the number of sensors attached to the LUN
        if ((ctx->lun == lun0) && (numSensors > 0))
        {
            sdrCount =
                (numSensors > maxSensorsPerLUN) ? maxSensorsPerLUN : numSensors;
        }
        else if ((ctx->lun == lun1) && (numSensors > maxSensorsPerLUN))
        {
            sdrCount = (numSensors > (2 * maxSensorsPerLUN))
                           ? maxSensorsPerLUN
                           : (numSensors - maxSensorsPerLUN) & maxSensorsPerLUN;
        }
        else if (ctx->lun == lun3)
        {
            if (numSensors <= maxIPMISensors)
            {
                sdrCount = (numSensors - (2 * maxSensorsPerLUN)) &
                           maxSensorsPerLUN;
            }
            else
            {
                throw std::out_of_range(
                    "Maximum number of IPMI sensors exceeded.");
            }
        }
    }
    else
    {
        return ipmi::responseInvalidFieldRequest();
    }

    // Flag which LUNs have sensors associated
    if (numSensors > 0)
    {
        lunsAndDynamicPopulation |= 1;
    }
    if (numSensors > maxSensorsPerLUN)
    {
        lunsAndDynamicPopulation |= 2;
    }
    if (numSensors >= (maxSensorsPerLUN * 2))
    {
        lunsAndDynamicPopulation |= 8;
    }
    if (numSensors > maxIPMISensors)
    {
        throw std::out_of_range("Maximum number of IPMI sensors exceeded.");
    }

    return ipmi::responseSuccess(sdrCount, lunsAndDynamicPopulation,
                                 sdrLastAdd);
}

/* end sensor commands */

/* storage commands */

ipmi::RspType<uint8_t,  // sdr version
              uint16_t, // record count
              uint16_t, // free space
              uint32_t, // most recent addition
              uint32_t, // most recent erase
              uint8_t   // operationSupport
              >
    ipmiStorageGetSDRRepositoryInfo(ipmi::Context::ptr ctx)
{
    constexpr const uint16_t unspecifiedFreeSpace = 0xFFFF;
    uint16_t recordCount =
        ipmi::getNumberOfSensors() + ipmi::sensor::getOtherSensorsCount(ctx);

    uint8_t operationSupport = static_cast<uint8_t>(
        SdrRepositoryInfoOps::overflow); // write not supported

    operationSupport |=
        static_cast<uint8_t>(SdrRepositoryInfoOps::allocCommandSupported);
    operationSupport |= static_cast<uint8_t>(
        SdrRepositoryInfoOps::reserveSDRRepositoryCommandSupported);
    return ipmi::responseSuccess(ipmiSdrVersion, recordCount,
                                 unspecifiedFreeSpace, sdrLastAdd,
                                 sdrLastRemove, operationSupport);
}

/** @brief implements the get SDR allocation info command
 *
 *  @returns IPMI completion code plus response data
 *   - allocUnits    - Number of possible allocation units
 *   - allocUnitSize - Allocation unit size in bytes.
 *   - allocUnitFree - Number of free allocation units
 *   - allocUnitLargestFree - Largest free block in allocation units
 *   - maxRecordSize    - Maximum record size in allocation units.
 */
ipmi::RspType<uint16_t, // allocUnits
              uint16_t, // allocUnitSize
              uint16_t, // allocUnitFree
              uint16_t, // allocUnitLargestFree
              uint8_t   // maxRecordSize
              >
    ipmiStorageGetSDRAllocationInfo()
{
    // 0000h unspecified number of alloc units
    constexpr uint16_t allocUnits = 0;

    constexpr uint16_t allocUnitFree = 0;
    constexpr uint16_t allocUnitLargestFree = 0;
    // only allow one block at a time
    constexpr uint8_t maxRecordSize = 1;

    return ipmi::responseSuccess(allocUnits, maxSDRTotalSize, allocUnitFree,
                                 allocUnitLargestFree, maxRecordSize);
}

/** @brief implements the reserve SDR command
 *  @returns IPMI completion code plus response data
 *   - sdrReservationID
 */
ipmi::RspType<uint16_t> ipmiStorageReserveSDR()
{
    sdrReservationID++;
    if (sdrReservationID == 0)
    {
        sdrReservationID++;
    }

    return ipmi::responseSuccess(sdrReservationID);
}

ipmi::RspType<uint16_t,            // next record ID
              std::vector<uint8_t> // payload
              >
    ipmiStorageGetSDR(ipmi::Context::ptr ctx, uint16_t reservationID,
                      uint16_t recordID, uint8_t offset, uint8_t bytesToRead)
{
    // reservation required for partial reads with non zero offset into
    // record
    if ((sdrReservationID == 0 || reservationID != sdrReservationID) && offset)
    {
        lg2::error("ipmiStorageGetSDR: responseInvalidReservationId");
        return ipmi::responseInvalidReservationId();
    }

    auto& sensorTree = getSensorTree();
    if (!getSensorSubtree(sensorTree) && sensorTree.empty())
    {
        lg2::error("ipmiStorageGetSDR: getSensorSubtree error");
        return ipmi::responseResponseError();
    }

    auto& ipmiDecoratorPaths = getIpmiDecoratorPaths(ctx);

    std::vector<uint8_t> record;
    int nextRecordId = getSensorDataRecord(
        ctx, ipmiDecoratorPaths.value_or(std::unordered_set<std::string>()),
        record, recordID, offset + bytesToRead);

    if (nextRecordId < 0)
    {
        lg2::error("ipmiStorageGetSDR: fail to get SDR");
        return ipmi::responseInvalidFieldRequest();
    }
    get_sdr::SensorDataRecordHeader* hdr =
        reinterpret_cast<get_sdr::SensorDataRecordHeader*>(record.data());
    if (!hdr)
    {
        lg2::error("ipmiStorageGetSDR: record header is null");
        return ipmi::responseSuccess(nextRecordId, record);
    }

    size_t sdrLength =
        sizeof(get_sdr::SensorDataRecordHeader) + hdr->record_length;
    if (offset >= sdrLength)
    {
        lg2::error("ipmiStorageGetSDR: offset is outside the record");
        return ipmi::responseParmOutOfRange();
    }
    if (sdrLength < (offset + bytesToRead))
    {
        bytesToRead = sdrLength - offset;
    }

    uint8_t* respStart = reinterpret_cast<uint8_t*>(hdr) + offset;
    if (!respStart)
    {
        lg2::error("ipmiStorageGetSDR: record is null");
        return ipmi::responseSuccess(nextRecordId, record);
    }

    std::vector<uint8_t> recordData(respStart, respStart + bytesToRead);

    return ipmi::responseSuccess(nextRecordId, recordData);
}
namespace dcmi
{

std::tuple<uint8_t,                // Total of instance sensors
           std::vector<sensorInfo> // The list of sensors
           >
    getSensorsByEntityId(ipmi::Context::ptr ctx, uint8_t entityId,
                         uint8_t entityInstance, uint8_t instanceStart)
{
    std::vector<sensorInfo> sensorList;
    uint8_t totalInstSensor = 0;
    auto match = ipmi::dcmi::validEntityId.find(entityId);

    if (match == ipmi::dcmi::validEntityId.end())
    {
        return std::make_tuple(totalInstSensor, sensorList);
    }

    auto& sensorTree = getSensorTree();
    if (!getSensorSubtree(sensorTree) && sensorTree.empty())
    {
        return std::make_tuple(totalInstSensor, sensorList);
    }

    auto& ipmiDecoratorPaths = getIpmiDecoratorPaths(ctx);

    size_t invalidSensorNumberErrCount = 0;
    for (const auto& sensor : sensorTree)
    {
        const std::string& sensorObjPath = sensor.first;
        const auto& sensorTypeValue = getSensorTypeFromPath(sensorObjPath);

        /*
         * In the DCMI specification, it only supports the sensor type is 0x01
         * (temperature type) for both Get Sensor Info and Get Temperature
         * Readings commands.
         */
        if (sensorTypeValue != ipmi::dcmi::temperatureSensorType)
        {
            continue;
        }

        const auto& connection = sensor.second.begin()->first;
        DbusInterfaceMap sensorMap;

        if (!getSensorMap(ctx, connection, sensorObjPath, sensorMap,
                          sensorMapSdrUpdatePeriod))
        {
            lg2::error("Failed to update sensor map for threshold sensor, "
                       "service: {SERVICE}, path: {PATH}",
                       "SERVICE", connection, "PATH", sensorObjPath);
            continue;
        }

        uint8_t entityIdValue = 0;
        uint8_t entityInstanceValue = 0;

        /*
         * Get the Entity ID, Entity Instance information which are configured
         * in the Entity-Manger.
         */
        updateIpmiFromAssociation(
            sensorObjPath,
            ipmiDecoratorPaths.value_or(std::unordered_set<std::string>()),
            sensorMap, entityIdValue, entityInstanceValue);

        if (entityIdValue == match->first || entityIdValue == match->second)
        {
            totalInstSensor++;

            /*
             * When Entity Instance parameter is not 0, we only get the first
             * sensor whose Entity Instance number is equal input Entity
             * Instance parameter.
             */
            if (entityInstance)
            {
                if (!sensorList.empty())
                {
                    continue;
                }

                if (entityInstanceValue == entityInstance)
                {
                    auto recordId = getSensorNumberFromPath(sensorObjPath);
                    if (recordId == invalidSensorNumber)
                    {
                        ++invalidSensorNumberErrCount;
                        continue;
                    }
                    sensorList.emplace_back(sensorObjPath, sensorTypeValue,
                                            recordId, entityIdValue,
                                            entityInstanceValue);
                }
            }
            else if (entityInstanceValue >= instanceStart)
            {
                auto recordId = getSensorNumberFromPath(sensorObjPath);
                if (recordId == invalidSensorNumber)
                {
                    ++invalidSensorNumberErrCount;
                    continue;
                }
                sensorList.emplace_back(sensorObjPath, sensorTypeValue,
                                        recordId, entityIdValue,
                                        entityInstanceValue);
            }
        }
    }
    if (invalidSensorNumberErrCount != 0)
    {
        lg2::error("getSensorNumberFromPath returned invalidSensorNumber "
                   "{ERR_COUNT} times",
                   "ERR_COUNT", invalidSensorNumberErrCount);
    }

    auto cmpFunc = [](sensorInfo first, sensorInfo second) {
        return first.entityInstance <= second.entityInstance;
    };

    sort(sensorList.begin(), sensorList.end(), cmpFunc);

    return std::make_tuple(totalInstSensor, sensorList);
}

std::tuple<bool,    // Reading result
           uint7_t, // Temp value
           bool>    // Sign bit
    readTemp(ipmi::Context::ptr ctx, const std::string& objectPath)
{
    std::string service{};
    boost::system::error_code ec =
        ipmi::getService(ctx, sensor::sensorInterface, objectPath, service);
    if (ec.value())
    {
        return std::make_tuple(false, 0, false);
    }

    ipmi::PropertyMap properties{};
    ec = ipmi::getAllDbusProperties(ctx, service, objectPath,
                                    sensor::sensorInterface, properties);
    if (ec.value())
    {
        return std::make_tuple(false, 0, false);
    }

    auto scaleIt = properties.find("Scale");
    double scaleVal = 0.0;
    if (scaleIt != properties.end())
    {
        scaleVal = std::visit(ipmi::VariantToDoubleVisitor(), scaleIt->second);
    }

    auto tempValIt = properties.find("Value");
    double tempVal = 0.0;
    if (tempValIt == properties.end())
    {
        return std::make_tuple(false, 0, false);
    }

    const double maxTemp = 127;
    double absTempVal = 0.0;
    bool signBit = false;

    tempVal = std::visit(ipmi::VariantToDoubleVisitor(), tempValIt->second);
    tempVal = std::pow(10, scaleVal) * tempVal;
    absTempVal = std::abs(tempVal);
    absTempVal = std::min(absTempVal, maxTemp);
    signBit = (tempVal < 0) ? true : false;

    return std::make_tuple(true, static_cast<uint7_t>(absTempVal), signBit);
}

ipmi::RspType<uint8_t,              // No of instances for requested id
              uint8_t,              // No of record ids in the response
              std::vector<uint16_t> // SDR Record ID corresponding to the Entity
                                    // IDs
              >
    getSensorInfo(ipmi::Context::ptr ctx, uint8_t sensorType, uint8_t entityId,
                  uint8_t entityInstance, uint8_t instanceStart)
{
    auto match = ipmi::dcmi::validEntityId.find(entityId);
    if (match == ipmi::dcmi::validEntityId.end())
    {
        lg2::error("Unknown Entity ID: {ENTITY_ID}", "ENTITY_ID", entityId);

        return ipmi::responseInvalidFieldRequest();
    }

    if (sensorType != ipmi::dcmi::temperatureSensorType)
    {
        lg2::error("Invalid sensor type: {SENSOR_TYPE}", "SENSOR_TYPE",
                   sensorType);

        return ipmi::responseInvalidFieldRequest();
    }

    std::vector<uint16_t> sensorRec{};
    const auto& [totalSensorInst, sensorList] =
        getSensorsByEntityId(ctx, entityId, entityInstance, instanceStart);

    if (sensorList.empty())
    {
        return ipmi::responseSuccess(totalSensorInst, 0, sensorRec);
    }

    /*
     * As DCMI specification, the maximum number of Record Ids of response data
     * is 1 if Entity Instance paramter is not 0. Else the maximum number of
     * Record Ids of response data is 8. Therefore, not all of sensors are shown
     * in response data.
     */
    uint8_t numOfRec = (entityInstance != 0) ? 1 : ipmi::dcmi::maxRecords;

    for (const auto& sensor : sensorList)
    {
        sensorRec.emplace_back(sensor.recordId);
        if (sensorRec.size() >= numOfRec)
        {
            break;
        }
    }

    return ipmi::responseSuccess(
        totalSensorInst, static_cast<uint8_t>(sensorRec.size()), sensorRec);
}

ipmi::RspType<uint8_t,                // No of instances for requested id
              uint8_t,                // No of record ids in the response
              std::vector<            // Temperature Data
                  std::tuple<uint7_t, // Temperature value
                             bool,    // Sign bit
                             uint8_t  // Entity Instance of sensor
                             >>>
    getTempReadings(ipmi::Context::ptr ctx, uint8_t sensorType,
                    uint8_t entityId, uint8_t entityInstance,
                    uint8_t instanceStart)
{
    auto match = ipmi::dcmi::validEntityId.find(entityId);
    if (match == ipmi::dcmi::validEntityId.end())
    {
        lg2::error("Unknown Entity ID: {ENTITY_ID}", "ENTITY_ID", entityId);

        return ipmi::responseInvalidFieldRequest();
    }

    if (sensorType != ipmi::dcmi::temperatureSensorType)
    {
        lg2::error("Invalid sensor type: {SENSOR_TYPE}", "SENSOR_TYPE",
                   sensorType);

        return ipmi::responseInvalidFieldRequest();
    }

    std::vector<std::tuple<uint7_t, bool, uint8_t>> tempReadingVal{};
    const auto& [totalSensorInst, sensorList] =
        getSensorsByEntityId(ctx, entityId, entityInstance, instanceStart);

    if (sensorList.empty())
    {
        return ipmi::responseSuccess(totalSensorInst, 0, tempReadingVal);
    }

    /*
     * As DCMI specification, the maximum number of Record Ids of response data
     * is 1 if Entity Instance paramter is not 0. Else the maximum number of
     * Record Ids of response data is 8. Therefore, not all of sensors are shown
     * in response data.
     */
    uint8_t numOfRec = (entityInstance != 0) ? 1 : ipmi::dcmi::maxRecords;

    for (const auto& sensor : sensorList)
    {
        const auto& [readResult, tempVal, signBit] =
            readTemp(ctx, sensor.objectPath);

        if (readResult)
        {
            tempReadingVal.emplace_back(
                std::make_tuple(tempVal, signBit, sensor.entityInstance));

            if (tempReadingVal.size() >= numOfRec)
            {
                break;
            }
        }
    }

    return ipmi::responseSuccess(totalSensorInst,
                                 static_cast<uint8_t>(tempReadingVal.size()),
                                 tempReadingVal);
}

} // namespace dcmi

/* end storage commands */

void registerSensorFunctions()
{
    // <Platform Event>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdPlatformEvent,
                          ipmi::Privilege::Operator, ipmiSenPlatformEvent);

    // <Set Sensor Reading and Event Status>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdSetSensorReadingAndEvtSts,
                          ipmi::Privilege::Operator, ipmiSetSensorReading);

    // <Get Sensor Reading>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdGetSensorReading,
                          ipmi::Privilege::User, ipmiSenGetSensorReading);

    // <Get Sensor Threshold>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdGetSensorThreshold,
                          ipmi::Privilege::User, ipmiSenGetSensorThresholds);

    // <Set Sensor Threshold>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdSetSensorThreshold,
                          ipmi::Privilege::Operator,
                          ipmiSenSetSensorThresholds);

    // <Get Sensor Event Enable>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdGetSensorEventEnable,
                          ipmi::Privilege::User, ipmiSenGetSensorEventEnable);

    // <Get Sensor Event Status>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdGetSensorEventStatus,
                          ipmi::Privilege::User, ipmiSenGetSensorEventStatus);

    // register all storage commands for both Sensor and Storage command
    // versions

    // <Get SDR Repository Info>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetSdrRepositoryInfo,
                          ipmi::Privilege::User,
                          ipmiStorageGetSDRRepositoryInfo);

    // <Get Device SDR Info>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdGetDeviceSdrInfo,
                          ipmi::Privilege::User, ipmiSensorGetDeviceSdrInfo);

    // <Get SDR Allocation Info>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetSdrRepositoryAllocInfo,
                          ipmi::Privilege::User,
                          ipmiStorageGetSDRAllocationInfo);

    // <Reserve SDR Repo>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdReserveDeviceSdrRepository,
                          ipmi::Privilege::User, ipmiStorageReserveSDR);

    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdReserveSdrRepository,
                          ipmi::Privilege::User, ipmiStorageReserveSDR);

    // <Get Sdr>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdGetDeviceSdr,
                          ipmi::Privilege::User, ipmiStorageGetSDR);

    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetSdr, ipmi::Privilege::User,
                          ipmiStorageGetSDR);
    // <Get DCMI Sensor Info>
    ipmi::registerGroupHandler(
        ipmi::prioOpenBmcBase, ipmi::groupDCMI,
        ipmi::dcmi::cmdGetDcmiSensorInfo, ipmi::Privilege::Operator,
        ipmi::dcmi::getSensorInfo);
    // <Get Temperature Readings>
    ipmi::registerGroupHandler(
        ipmi::prioOpenBmcBase, ipmi::groupDCMI,
        ipmi::dcmi::cmdGetTemperatureReadings, ipmi::Privilege::User,
        ipmi::dcmi::getTempReadings);
}
} // namespace ipmi
