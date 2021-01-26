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

#include "dbus-sdr/sensorcommands.hpp"

#include "dbus-sdr/sdrutils.hpp"
#include "dbus-sdr/sensorutils.hpp"
#include "dbus-sdr/storagecommands.hpp"

#include <algorithm>
#include <array>
#include <boost/algorithm/string.hpp>
#include <boost/container/flat_map.hpp>
#include <chrono>
#include <cmath>
#include <cstring>
#include <iostream>
#include <ipmid/api.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <map>
#include <memory>
#include <optional>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>

namespace ipmi
{
using SDRObjectType =
    boost::container::flat_map<uint16_t, std::vector<uint8_t>>;

static constexpr int sensorMapUpdatePeriod = 10;

constexpr size_t maxSDRTotalSize =
    76; // Largest SDR Record Size (type 01) + SDR Overheader Size
constexpr static const uint32_t noTimestamp = 0xFFFFFFFF;

static uint16_t sdrReservationID;
static uint32_t sdrLastAdd = noTimestamp;
static uint32_t sdrLastRemove = noTimestamp;
static constexpr size_t lastRecordIndex = 0xFFFF;
static constexpr int GENERAL_ERROR = -1;

SDRObjectType sensorDataRecords;

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
                 {"power", SensorUnits::watts}}};

void registerSensorFunctions() __attribute__((constructor));

static sdbusplus::bus::match::match sensorAdded(
    *getSdBus(),
    "type='signal',member='InterfacesAdded',arg0path='/xyz/openbmc_project/"
    "sensors/'",
    [](sdbusplus::message::message& m) {
        getSensorTree().clear();
        sdrLastAdd = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    });

static sdbusplus::bus::match::match sensorRemoved(
    *getSdBus(),
    "type='signal',member='InterfacesRemoved',arg0path='/xyz/openbmc_project/"
    "sensors/'",
    [](sdbusplus::message::message& m) {
        getSensorTree().clear();
        sdrLastRemove = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();
    });

// this keeps track of deassertions for sensor event status command. A
// deasertion can only happen if an assertion was seen first.
static boost::container::flat_map<
    std::string, boost::container::flat_map<std::string, std::optional<bool>>>
    thresholdDeassertMap;

static sdbusplus::bus::match::match thresholdChanged(
    *getSdBus(),
    "type='signal',member='PropertiesChanged',interface='org.freedesktop.DBus."
    "Properties',arg0namespace='xyz.openbmc_project.Sensor.Threshold'",
    [](sdbusplus::message::message& m) {
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
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "thresholdChanged: Assert non bool");
                return;
            }
            if (*ptr)
            {
                phosphor::logging::log<phosphor::logging::level::INFO>(
                    "thresholdChanged: Assert",
                    phosphor::logging::entry("SENSOR=%s", m.get_path()));
                thresholdDeassertMap[m.get_path()][findAssert->first] = *ptr;
            }
            else
            {
                auto& value =
                    thresholdDeassertMap[m.get_path()][findAssert->first];
                if (value)
                {
                    phosphor::logging::log<phosphor::logging::level::INFO>(
                        "thresholdChanged: deassert",
                        phosphor::logging::entry("SENSOR=%s", m.get_path()));
                    value = *ptr;
                }
            }
        }
    });

static void getSensorMaxMin(const DbusInterfaceMap& sensorMap, double& max,
                            double& min)
{
    max = 127;
    min = -128;

    auto sensorObject = sensorMap.find("xyz.openbmc_project.Sensor.Value");
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
            min = std::min(value, min);
        }
        if (upper != critical->second.end())
        {
            double value = std::visit(VariantToDoubleVisitor(), upper->second);
            max = std::max(value, max);
        }
    }
    if (warning != sensorMap.end())
    {

        auto lower = warning->second.find("WarningLow");
        auto upper = warning->second.find("WarningHigh");
        if (lower != warning->second.end())
        {
            double value = std::visit(VariantToDoubleVisitor(), lower->second);
            min = std::min(value, min);
        }
        if (upper != warning->second.end())
        {
            double value = std::visit(VariantToDoubleVisitor(), upper->second);
            max = std::max(value, max);
        }
    }
}

static bool getSensorMap(ipmi::Context::ptr ctx, std::string sensorConnection,
                         std::string sensorPath, DbusInterfaceMap& sensorMap)
{
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
            .count() > sensorMapUpdatePeriod)
    {
        updateTimeMap[sensorConnection] = now;

        ObjectValueTree managedObjects;
        boost::system::error_code ec = getManagedObjects(
            ctx, sensorConnection.c_str(), "/", managedObjects);
        if (ec)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "GetMangagedObjects for getSensorMap failed",
                phosphor::logging::entry("ERROR=%s", ec.message().c_str()));

            return false;
        }

        SensorCache[sensorConnection] = managedObjects;
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

ipmi::RspType<> ipmiSenPlatformEvent(uint8_t generatorID, uint8_t evmRev,
                                     uint8_t sensorType, uint8_t sensorNum,
                                     uint8_t eventType, uint8_t eventData1,
                                     std::optional<uint8_t> eventData2,
                                     std::optional<uint8_t> eventData3)
{
    return ipmi::responseSuccess();
}

ipmi::RspType<uint8_t, uint8_t, uint8_t, std::optional<uint8_t>>
    ipmiSenGetSensorReading(ipmi::Context::ptr ctx, uint8_t sensnum)
{
    std::string connection;
    std::string path;

    auto status = getSensorConnection(ctx, sensnum, connection, path);
    if (status)
    {
        return ipmi::response(status);
    }

    DbusInterfaceMap sensorMap;
    if (!getSensorMap(ctx, connection, path, sensorMap))
    {
        return ipmi::responseResponseError();
    }
    auto sensorObject = sensorMap.find("xyz.openbmc_project.Sensor.Value");

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
    uint8_t lowerCritical, uint8_t lowerNonRecoverable,
    uint8_t upperNonCritical, uint8_t upperCritical,
    uint8_t upperNonRecoverable)
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
        auto sensorPair = sensorMap.find("xyz.openbmc_project.Sensor.Value");

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
                resp.warningHigh = scaleIPMIValueFromDouble(
                    value, mValue, rExp, bValue, bExp, bSigned);
            }
            if (warningLow != warningMap.end())
            {
                double value =
                    std::visit(VariantToDoubleVisitor(), warningLow->second);
                resp.warningLow = scaleIPMIValueFromDouble(
                    value, mValue, rExp, bValue, bExp, bSigned);
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
                resp.criticalHigh = scaleIPMIValueFromDouble(
                    value, mValue, rExp, bValue, bExp, bSigned);
            }
            if (criticalLow != criticalMap.end())
            {
                double value =
                    std::visit(VariantToDoubleVisitor(), criticalLow->second);
                resp.criticalLow = scaleIPMIValueFromDouble(
                    value, mValue, rExp, bValue, bExp, bSigned);
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
    catch (std::exception&)
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

    auto status = getSensorConnection(ctx, sensorNum, connection, path);
    if (status)
    {
        return ipmi::response(status);
    }

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
                assertionEnabledLsb |= static_cast<uint8_t>(
                    IPMISensorEventEnableThresholds::upperNonCriticalGoingHigh);
                deassertionEnabledLsb |= static_cast<uint8_t>(
                    IPMISensorEventEnableThresholds::upperNonCriticalGoingLow);
            }
            if (warningLow != warningMap.end())
            {
                assertionEnabledLsb |= static_cast<uint8_t>(
                    IPMISensorEventEnableThresholds::lowerNonCriticalGoingLow);
                deassertionEnabledLsb |= static_cast<uint8_t>(
                    IPMISensorEventEnableThresholds::lowerNonCriticalGoingHigh);
            }
        }
        if (criticalInterface != sensorMap.end())
        {
            auto& criticalMap = criticalInterface->second;

            auto criticalHigh = criticalMap.find("CriticalHigh");
            auto criticalLow = criticalMap.find("CriticalLow");

            if (criticalHigh != criticalMap.end())
            {
                assertionEnabledMsb |= static_cast<uint8_t>(
                    IPMISensorEventEnableThresholds::upperCriticalGoingHigh);
                deassertionEnabledMsb |= static_cast<uint8_t>(
                    IPMISensorEventEnableThresholds::upperCriticalGoingLow);
            }
            if (criticalLow != criticalMap.end())
            {
                assertionEnabledLsb |= static_cast<uint8_t>(
                    IPMISensorEventEnableThresholds::lowerCriticalGoingLow);
                deassertionEnabledLsb |= static_cast<uint8_t>(
                    IPMISensorEventEnableThresholds::lowerCriticalGoingHigh);
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
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiSenGetSensorEventStatus: Sensor connection Error",
            phosphor::logging::entry("SENSOR=%d", sensorNum));
        return ipmi::response(status);
    }

    DbusInterfaceMap sensorMap;
    if (!getSensorMap(ctx, connection, path, sensorMap))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiSenGetSensorEventStatus: Sensor Mapping Error",
            phosphor::logging::entry("SENSOR=%s", path.c_str()));
        return ipmi::responseResponseError();
    }
    auto warningInterface =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Warning");
    auto criticalInterface =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Critical");

    uint8_t sensorEventStatus =
        static_cast<uint8_t>(IPMISensorEventEnableByte2::sensorScanningEnable);

    std::optional<bool> criticalDeassertHigh =
        thresholdDeassertMap[path]["CriticalAlarmHigh"];
    std::optional<bool> criticalDeassertLow =
        thresholdDeassertMap[path]["CriticalAlarmLow"];
    std::optional<bool> warningDeassertHigh =
        thresholdDeassertMap[path]["WarningAlarmHigh"];
    std::optional<bool> warningDeassertLow =
        thresholdDeassertMap[path]["WarningAlarmLow"];

    std::bitset<16> assertions = 0;
    std::bitset<16> deassertions = 0;

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
                assertions.set(
                    static_cast<size_t>(IPMIGetSensorEventEnableThresholds::
                                            upperNonCriticalGoingHigh));
            }
            if (warningLowAlarm)
            {
                assertions.set(
                    static_cast<size_t>(IPMIGetSensorEventEnableThresholds::
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
                assertions.set(
                    static_cast<size_t>(IPMIGetSensorEventEnableThresholds::
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

static int getSensorDataRecords(ipmi::Context::ptr ctx)
{
    auto& sensorTree = getSensorTree();
    size_t recordID = 0;
    size_t fruCount = 0;

    ipmi::Cc ret = ipmi::storage::getFruSdrCount(ctx, fruCount);
    if (ret != ipmi::ccSuccess)
    {
        return GENERAL_ERROR;
    }

    size_t lastRecord =
        sensorTree.size() + fruCount + ipmi::storage::type12Count - 1;
    if (lastRecord > lastRecordIndex)
    {
        return GENERAL_ERROR;
    }

    std::string connection;
    std::string path;
    for (const auto& sensor : sensorTree)
    {

        connection = sensor.second.begin()->first;
        path = sensor.first;

        DbusInterfaceMap sensorMap;
        if (!getSensorMap(ctx, connection, path, sensorMap))
        {
            return GENERAL_ERROR;
        }
        uint16_t sensorNum = getSensorNumberFromPath(path);
        if (sensorNum == invalidSensorNumber)
        {
            return GENERAL_ERROR;
        }
        uint8_t sensornumber = static_cast<uint8_t>(sensorNum);
        uint8_t lun = static_cast<uint8_t>(sensorNum >> 8);

        get_sdr::SensorDataFullRecord record = {0};

        get_sdr::header::set_record_id(
            recordID,
            reinterpret_cast<get_sdr::SensorDataRecordHeader*>(&record));
        record.header.sdr_version = ipmiSdrVersion;
        record.header.record_type = get_sdr::SENSOR_DATA_FULL_RECORD;
        record.header.record_length = sizeof(get_sdr::SensorDataFullRecord) -
                                      sizeof(get_sdr::SensorDataRecordHeader);
        record.key.owner_id = 0x20;
        record.key.owner_lun = lun;
        record.key.sensor_number = sensornumber;

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

        auto sensorObject = sensorMap.find("xyz.openbmc_project.Sensor.Value");
        if (sensorObject == sensorMap.end())
        {
            return GENERAL_ERROR;
        }

        uint8_t entityId = 0;
        uint8_t entityInstance = 0x01;

        // follow the association chain to get the parent board's entityid and
        // entityInstance
        updateIpmiFromAssociation(path, sensorMap, entityId, entityInstance);

        record.body.entity_id = entityId;
        record.body.entity_instance = entityInstance;

        auto maxObject = sensorObject->second.find("MaxValue");
        auto minObject = sensorObject->second.find("MinValue");

        // If min and/or max are left unpopulated,
        // then default to what a signed byte would be, namely (-128,127) range.
        auto max = static_cast<double>(std::numeric_limits<int8_t>::max());
        auto min = static_cast<double>(std::numeric_limits<int8_t>::lowest());
        if (maxObject != sensorObject->second.end())
        {
            max = std::visit(VariantToDoubleVisitor(), maxObject->second);
        }

        if (minObject != sensorObject->second.end())
        {
            min = std::visit(VariantToDoubleVisitor(), minObject->second);
        }

        int16_t mValue = 0;
        int8_t rExp = 0;
        int16_t bValue = 0;
        int8_t bExp = 0;
        bool bSigned = false;

        if (!getSensorAttributes(max, min, mValue, rExp, bValue, bExp, bSigned))
        {
            return GENERAL_ERROR;
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
        std::string name;
        size_t nameStart = path.rfind("/");
        if (nameStart != std::string::npos)
        {
            name = path.substr(nameStart + 1, std::string::npos - nameStart);
        }

        std::replace(name.begin(), name.end(), '_', ' ');
        if (name.size() > FULL_RECORD_ID_STR_MAX_LENGTH)
        {
            // try to not truncate by replacing common words
            constexpr std::array<std::pair<const char*, const char*>, 2>
                replaceWords = {std::make_pair("Output", "Out"),
                                std::make_pair("Input", "In")};
            for (const auto& [find, replace] : replaceWords)
            {
                boost::replace_all(name, find, replace);
            }

            name.resize(FULL_RECORD_ID_STR_MAX_LENGTH);
        }
        record.body.id_string_info = name.size();
        std::strncpy(record.body.id_string, name.c_str(),
                     sizeof(record.body.id_string));

        IPMIThresholds thresholdData;
        try
        {
            thresholdData = getIPMIThresholds(sensorMap);
        }
        catch (std::exception&)
        {
            return GENERAL_ERROR;
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
            record.body.upper_noncritical_threshold =
                *thresholdData.warningHigh;
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

        // insert the record into the map
        std::vector<uint8_t> sdr;
        sdr.insert(sdr.end(), (uint8_t*)&record,
                   ((uint8_t*)&record) + sizeof(record));
        sensorDataRecords.insert_or_assign(recordID, sdr);
        recordID++;
    }

    size_t nonSensorRecCount = fruCount + ipmi::storage::type12Count;
    do
    {
        size_t fruIndex = recordID - sensorTree.size();

        if (fruIndex >= fruCount)
        {
            // handle type 12 hardcoded records
            size_t type12Index = fruIndex - fruCount;
            if (type12Index >= ipmi::storage::type12Count)
            {
                return GENERAL_ERROR;
            }
            std::vector<uint8_t> record =
                ipmi::storage::getType12SDRs(type12Index, recordID);
            sensorDataRecords.insert_or_assign(recordID, record);
        }
        else
        {
            // handle fru records
            get_sdr::SensorDataFruRecord data;
            ret = ipmi::storage::getFruSdrs(ctx, fruIndex, data);
            if (ret != IPMI_CC_OK)
            {
                return GENERAL_ERROR;
            }
            get_sdr::header::set_record_id(
                recordID,
                reinterpret_cast<get_sdr::SensorDataRecordHeader*>(&data));

            std::vector<uint8_t> record;
            record.insert(record.end(), (uint8_t*)&data,
                          ((uint8_t*)&data) + sizeof(data));
            sensorDataRecords.insert_or_assign(recordID, record);
        }
        recordID++;
    } while (--nonSensorRecCount);
    return 0;
}

/** @brief implements the get SDR Info command
 *  @param count - Operation
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
                               std::optional<uint8_t> count)
{
    auto& sensorTree = getSensorTree();
    uint8_t sdrCount = 0;
    // Sensors are dynamically allocated, and there is at least one LUN
    uint8_t lunsAndDynamicPopulation = 0x80;
    constexpr uint8_t getSdrCount = 0x01;
    constexpr uint8_t getSensorCount = 0x00;

    if (!getSensorSubtree(sensorTree) || sensorTree.empty())
    {
        return ipmi::responseResponseError();
    }

    if (sensorDataRecords.empty() && getSensorDataRecords(ctx))
    {
        return ipmi::responseResponseError();
    }

    uint16_t numSensors = sensorTree.size();
    if (count.value_or(0) == getSdrCount)
    {
        // Count the number of Type 1 SDR entries assigned to the LUN
        for (auto sdr : sensorDataRecords)
        {
            get_sdr::SensorDataRecordHeader* hdr =
                reinterpret_cast<get_sdr::SensorDataRecordHeader*>(
                    sdr.second.data());
            if (hdr && hdr->record_type == get_sdr::SENSOR_DATA_FULL_RECORD)
            {
                get_sdr::SensorDataFullRecord* record =
                    reinterpret_cast<get_sdr::SensorDataFullRecord*>(
                        sdr.second.data());
                if (ctx->lun == record->key.owner_lun)
                {
                    sdrCount++;
                }
            }
        }
    }
    else if (count.value_or(0) == getSensorCount)
    {
        // Return the number of sensors attached to the LUN
        if ((ctx->lun == 0) && (numSensors > 0))
        {
            sdrCount =
                (numSensors > maxSensorsPerLUN) ? maxSensorsPerLUN : numSensors;
        }
        else if ((ctx->lun == 1) && (numSensors > maxSensorsPerLUN))
        {
            sdrCount = (numSensors > (2 * maxSensorsPerLUN))
                           ? maxSensorsPerLUN
                           : (numSensors - maxSensorsPerLUN) & maxSensorsPerLUN;
        }
        else if (ctx->lun == 3)
        {
            if (numSensors <= maxIPMISensors)
            {
                sdrCount =
                    (numSensors - (2 * maxSensorsPerLUN)) & maxSensorsPerLUN;
            }
            else
            {
                // error
                throw std::out_of_range(
                    "Maximum number of IPMI sensors exceeded.");
            }
        }
    }
    else
    {
        return ipmi::responseInvalidFieldRequest();
    }

    // Get Sensor count. This returns the number of sensors
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
        // error
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
    auto& sensorTree = getSensorTree();
    constexpr const uint16_t unspecifiedFreeSpace = 0xFFFF;
    if (sensorTree.empty() && !getSensorSubtree(sensorTree))
    {
        return ipmi::responseResponseError();
    }

    size_t fruCount = 0;
    ipmi::Cc ret = ipmi::storage::getFruSdrCount(ctx, fruCount);
    if (ret != ipmi::ccSuccess)
    {
        return ipmi::response(ret);
    }

    uint16_t recordCount =
        sensorTree.size() + fruCount + ipmi::storage::type12Count;

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
        return ipmi::responseInvalidReservationId();
    }

    if (sensorDataRecords.empty() && getSensorDataRecords(ctx))
    {
        return ipmi::responseResponseError();
    }

    auto& sensorTree = getSensorTree();
    if (sensorTree.empty() && !getSensorSubtree(sensorTree))
    {
        return ipmi::responseResponseError();
    }

    size_t fruCount = 0;
    ipmi::Cc ret = ipmi::storage::getFruSdrCount(ctx, fruCount);
    if (ret != ipmi::ccSuccess)
    {
        return ipmi::response(ret);
    }

    size_t lastRecord =
        sensorTree.size() + fruCount + ipmi::storage::type12Count - 1;
    if (recordID == lastRecordIndex)
    {
        recordID = lastRecord;
    }
    if (recordID > lastRecord)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    get_sdr::SensorDataRecordHeader* hdr =
        reinterpret_cast<get_sdr::SensorDataRecordHeader*>(
            sensorDataRecords[recordID].data());

    if (!hdr)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error: record header is null");
        std::vector<uint8_t> emptyData;
        uint16_t nextRecordId = lastRecord > recordID ? recordID + 1 : 0XFFFF;
        return ipmi::responseSuccess(nextRecordId, emptyData);
    }

    size_t sdrLength =
        sizeof(get_sdr::SensorDataRecordHeader) + hdr->record_length;
    if (sdrLength < (offset + bytesToRead))
    {
        bytesToRead = sdrLength - offset;
    }

    uint8_t* respStart = reinterpret_cast<uint8_t*>(hdr) + offset;
    if (!respStart)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error: record is null");
        std::vector<uint8_t> emptyData;
        uint16_t nextRecordId = lastRecord > recordID ? recordID + 1 : 0XFFFF;
        return ipmi::responseSuccess(nextRecordId, emptyData);
    }

    std::vector<uint8_t> recordData(respStart, respStart + bytesToRead);
    uint16_t nextRecordId = lastRecord > recordID ? recordID + 1 : 0XFFFF;
    return ipmi::responseSuccess(nextRecordId, recordData);
}
/* end storage commands */

void registerSensorFunctions()
{
    // <Platform Event>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdPlatformEvent,
                          ipmi::Privilege::Operator, ipmiSenPlatformEvent);

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
}
} // namespace ipmi
