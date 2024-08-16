#pragma once

#include "config.h"

#include "sensorhandler.hpp"

#include <ipmid/api.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/message/types.hpp>

#include <cmath>

#ifdef FEATURE_SENSORS_CACHE

extern ipmi::sensor::SensorCacheMap sensorCacheMap;

// The signal's message type is 0x04 from DBus spec:
// https://dbus.freedesktop.org/doc/dbus-specification.html#message-protocol-messages
static constexpr auto msgTypeSignal = 0x04;

#endif

namespace ipmi
{
namespace sensor
{

using Assertion = uint16_t;
using Deassertion = uint16_t;
using AssertionSet = std::pair<Assertion, Deassertion>;
using Service = std::string;
using Path = std::string;
using Interface = std::string;
using ServicePath = std::pair<Path, Service>;
using Interfaces = std::vector<Interface>;
using MapperResponseType = std::map<Path, std::map<Service, Interfaces>>;
using PropertyMap = ipmi::PropertyMap;

using namespace phosphor::logging;

/** @brief Make assertion set from input data
 *  @param[in] cmdData - Input sensor data
 *  @return pair of assertion and deassertion set
 */
AssertionSet getAssertionSet(const SetSensorReadingReq& cmdData);

/** @brief send the message to DBus
 *  @param[in] msg - message to send
 *  @return failure status in IPMI error code
 */
ipmi_ret_t updateToDbus(IpmiUpdateData& msg);

namespace get
{

/** @brief Populate sensor name from the D-Bus property associated with the
 *         sensor. In the example entry from the yaml, the name of the D-bus
 *         property "AttemptsLeft" is the sensor name.
 *
 *         0x07:
 *            sensorType: 195
 *            path: /xyz/openbmc_project/state/host0
 *            sensorReadingType: 0x6F
 *            serviceInterface: org.freedesktop.DBus.Properties
 *            readingType: readingAssertion
 *            sensorNamePattern: nameProperty
 *            interfaces:
 *              xyz.openbmc_project.Control.Boot.RebootAttempts:
 *                AttemptsLeft:
 *                    Offsets:
 *                        0xFF:
 *                          type: uint32_t
 *
 *
 *  @param[in] sensorInfo - Dbus info related to sensor.
 *
 *  @return On success return the sensor name for the sensor.
 */
inline SensorName nameProperty(const Info& sensorInfo)
{
    return sensorInfo.propertyInterfaces.begin()->second.begin()->first;
}

/** @brief Populate sensor name from the D-Bus object associated with the
 *         sensor. If the object path is /system/chassis/motherboard/dimm0 then
 *         the leaf dimm0 is considered as the sensor name.
 *
 *  @param[in] sensorInfo - Dbus info related to sensor.
 *
 *  @return On success return the sensor name for the sensor.
 */
inline SensorName nameLeaf(const Info& sensorInfo)
{
    return sensorInfo.sensorPath.substr(
        sensorInfo.sensorPath.find_last_of('/') + 1,
        sensorInfo.sensorPath.length());
}

/** @brief Populate sensor name from the D-Bus object associated with the
 *         sensor and the property.
 *         If the object path is /xyz/openbmc_project/inventory/Fan0 and
 *         the property is Present, the leaf Fan0 and the Property is
 *         joined to Fan0_Present as the sensor name.
 *
 *  @param[in] sensorInfo - Dbus info related to sensor.
 *
 *  @return On success return the sensor name for the sensor.
 */
inline SensorName nameLeafProperty(const Info& sensorInfo)
{
    return nameLeaf(sensorInfo) + "_" + nameProperty(sensorInfo);
}

/** @brief Populate sensor name from the D-Bus object associated with the
 *         sensor. If the object path is /system/chassis/motherboard/cpu0/core0
 *         then the sensor name is cpu0_core0. The leaf and the parent is put
 *         together to get the sensor name.
 *
 *  @param[in] sensorInfo - Dbus info related to sensor.
 *
 *  @return On success return the sensor name for the sensor.
 */
SensorName nameParentLeaf(const Info& sensorInfo);

/**
 *  @brief Helper function to map the dbus info to sensor's assertion status
 *         for the get sensor reading command.
 *
 *  @param[in] sensorInfo - Dbus info related to sensor.
 *  @param[in] path - Dbus object path.
 *  @param[in] interface - Dbus interface.
 *
 *  @return Response for get sensor reading command.
 */
GetSensorResponse mapDbusToAssertion(const Info& sensorInfo,
                                     const InstancePath& path,
                                     const DbusInterface& interface);

#ifndef FEATURE_SENSORS_CACHE
/**
 *  @brief Map the Dbus info to sensor's assertion status in the Get sensor
 *         reading command response.
 *
 *  @param[in] sensorInfo - Dbus info related to sensor.
 *
 *  @return Response for get sensor reading command.
 */
GetSensorResponse assertion(const Info& sensorInfo);

/**
 *  @brief Maps the Dbus info to the reading field in the Get sensor reading
 *         command response.
 *
 *  @param[in] sensorInfo - Dbus info related to sensor.
 *
 *  @return Response for get sensor reading command.
 */
GetSensorResponse eventdata2(const Info& sensorInfo);

/**
 *  @brief readingAssertion is a case where the entire assertion state field
 *         serves as the sensor value.
 *
 *  @tparam T - type of the dbus property related to sensor.
 *  @param[in] sensorInfo - Dbus info related to sensor.
 *
 *  @return Response for get sensor reading command.
 */
template <typename T>
GetSensorResponse readingAssertion(const Info& sensorInfo)
{
    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};
    GetSensorResponse response{};

    enableScanning(&response);

    auto service = ipmi::getService(bus, sensorInfo.sensorInterface,
                                    sensorInfo.sensorPath);

    auto propValue = ipmi::getDbusProperty(
        bus, service, sensorInfo.sensorPath,
        sensorInfo.propertyInterfaces.begin()->first,
        sensorInfo.propertyInterfaces.begin()->second.begin()->first);

    setAssertionBytes(static_cast<uint16_t>(std::get<T>(propValue)), &response);

    return response;
}

/** @brief Map the Dbus info to the reading field in the Get sensor reading
 *         command response
 *
 *  @tparam T - type of the dbus property related to sensor.
 *  @param[in] sensorInfo - Dbus info related to sensor.
 *
 *  @return Response for get sensor reading command.
 */
template <typename T>
GetSensorResponse readingData(const Info& sensorInfo)
{
    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};

    GetSensorResponse response{};

    enableScanning(&response);

    auto service = ipmi::getService(bus, sensorInfo.sensorInterface,
                                    sensorInfo.sensorPath);

#ifdef UPDATE_FUNCTIONAL_ON_FAIL
    // Check the OperationalStatus interface for functional property
    if (sensorInfo.propertyInterfaces.begin()->first ==
        "xyz.openbmc_project.Sensor.Value")
    {
        bool functional = true;
        try
        {
            auto funcValue = ipmi::getDbusProperty(
                bus, service, sensorInfo.sensorPath,
                "xyz.openbmc_project.State.Decorator.OperationalStatus",
                "Functional");
            functional = std::get<bool>(funcValue);
        }
        catch (...)
        {
            // No-op if Functional property could not be found since this
            // check is only valid for Sensor.Value read for hwmonio
        }
        if (!functional)
        {
            throw SensorFunctionalError();
        }
    }
#endif

    auto propValue = ipmi::getDbusProperty(
        bus, service, sensorInfo.sensorPath,
        sensorInfo.propertyInterfaces.begin()->first,
        sensorInfo.propertyInterfaces.begin()->second.begin()->first);

    double value = std::get<T>(propValue) *
                   std::pow(10, sensorInfo.scale - sensorInfo.exponentR);
    int32_t rawData =
        (value - sensorInfo.scaledOffset) / sensorInfo.coefficientM;

    constexpr uint8_t sensorUnitsSignedBits = 2 << 6;
    constexpr uint8_t signedDataFormat = 0x80;
    // if sensorUnits1 [7:6] = 10b, sensor is signed
    int32_t minClamp;
    int32_t maxClamp;
    if ((sensorInfo.sensorUnits1 & sensorUnitsSignedBits) == signedDataFormat)
    {
        minClamp = std::numeric_limits<int8_t>::lowest();
        maxClamp = std::numeric_limits<int8_t>::max();
    }
    else
    {
        minClamp = std::numeric_limits<uint8_t>::lowest();
        maxClamp = std::numeric_limits<uint8_t>::max();
    }
    setReading(static_cast<uint8_t>(std::clamp(rawData, minClamp, maxClamp)),
               &response);

    if (!std::isfinite(value))
    {
        response.readingOrStateUnavailable = 1;
    }

    bool critAlarmHigh;
    try
    {
        critAlarmHigh = std::get<bool>(ipmi::getDbusProperty(
            bus, service, sensorInfo.sensorPath,
            "xyz.openbmc_project.Sensor.Threshold.Critical",
            "CriticalAlarmHigh"));
    }
    catch (const std::exception& e)
    {
        critAlarmHigh = false;
    }
    bool critAlarmLow;
    try
    {
        critAlarmLow = std::get<bool>(ipmi::getDbusProperty(
            bus, service, sensorInfo.sensorPath,
            "xyz.openbmc_project.Sensor.Threshold.Critical",
            "CriticalAlarmLow"));
    }
    catch (const std::exception& e)
    {
        critAlarmLow = false;
    }
    bool warningAlarmHigh;
    try
    {
        warningAlarmHigh = std::get<bool>(ipmi::getDbusProperty(
            bus, service, sensorInfo.sensorPath,
            "xyz.openbmc_project.Sensor.Threshold.Warning",
            "WarningAlarmHigh"));
    }
    catch (const std::exception& e)
    {
        warningAlarmHigh = false;
    }
    bool warningAlarmLow;
    try
    {
        warningAlarmLow = std::get<bool>(ipmi::getDbusProperty(
            bus, service, sensorInfo.sensorPath,
            "xyz.openbmc_project.Sensor.Threshold.Warning", "WarningAlarmLow"));
    }
    catch (const std::exception& e)
    {
        warningAlarmLow = false;
    }
    response.thresholdLevelsStates =
        (static_cast<uint8_t>(critAlarmHigh) << 3) |
        (static_cast<uint8_t>(critAlarmLow) << 2) |
        (static_cast<uint8_t>(warningAlarmHigh) << 1) |
        (static_cast<uint8_t>(warningAlarmLow));

    return response;
}

#else

/**
 *  @brief Map the Dbus info to sensor's assertion status in the Get sensor
 *         reading command response.
 *
 *  @param[in] id - The sensor id
 *  @param[in] sensorInfo - Dbus info related to sensor.
 *  @param[in] msg - Dbus message from match callback.
 *
 *  @return Response for get sensor reading command.
 */
std::optional<GetSensorResponse> assertion(uint8_t id, const Info& sensorInfo,
                                           const PropertyMap& properties);

/**
 *  @brief Maps the Dbus info to the reading field in the Get sensor reading
 *         command response.
 *
 *  @param[in] id - The sensor id
 *  @param[in] sensorInfo - Dbus info related to sensor.
 *  @param[in] msg - Dbus message from match callback.
 *
 *  @return Response for get sensor reading command.
 */
std::optional<GetSensorResponse> eventdata2(uint8_t id, const Info& sensorInfo,
                                            const PropertyMap& properties);

/**
 *  @brief readingAssertion is a case where the entire assertion state field
 *         serves as the sensor value.
 *
 *  @tparam T - type of the dbus property related to sensor.
 *  @param[in] id - The sensor id
 *  @param[in] sensorInfo - Dbus info related to sensor.
 *  @param[in] msg - Dbus message from match callback.
 *
 *  @return Response for get sensor reading command.
 */
template <typename T>
std::optional<GetSensorResponse> readingAssertion(
    uint8_t id, const Info& sensorInfo, const PropertyMap& properties)
{
    GetSensorResponse response{};
    enableScanning(&response);

    auto iter = properties.find(
        sensorInfo.propertyInterfaces.begin()->second.begin()->first);
    if (iter == properties.end())
    {
        return {};
    }

    setAssertionBytes(static_cast<uint16_t>(std::get<T>(iter->second)),
                      &response);

    if (!sensorCacheMap[id].has_value())
    {
        sensorCacheMap[id] = SensorData{};
    }
    sensorCacheMap[id]->response = response;
    return response;
}

/** @brief Get sensor reading from the dbus message from match
 *
 *  @tparam T - type of the dbus property related to sensor.
 *  @param[in] id - The sensor id
 *  @param[in] sensorInfo - Dbus info related to sensor.
 *  @param[in] msg - Dbus message from match callback.
 *
 *  @return Response for get sensor reading command.
 */
template <typename T>
std::optional<GetSensorResponse> readingData(uint8_t id, const Info& sensorInfo,
                                             const PropertyMap& properties)
{
    auto iter = properties.find("Functional");
    if (iter != properties.end())
    {
        sensorCacheMap[id]->functional = std::get<bool>(iter->second);
    }
    iter = properties.find("Available");
    if (iter != properties.end())
    {
        sensorCacheMap[id]->available = std::get<bool>(iter->second);
    }
#ifdef UPDATE_FUNCTIONAL_ON_FAIL
    if (sensorCacheMap[id])
    {
        if (!sensorCacheMap[id]->functional)
        {
            throw SensorFunctionalError();
        }
    }
#endif

    GetSensorResponse response{};

    enableScanning(&response);

    iter = properties.find(
        sensorInfo.propertyInterfaces.begin()->second.begin()->first);
    if (iter == properties.end())
    {
        return {};
    }

    double value = std::get<T>(iter->second) *
                   std::pow(10, sensorInfo.scale - sensorInfo.exponentR);
    int32_t rawData =
        (value - sensorInfo.scaledOffset) / sensorInfo.coefficientM;

    constexpr uint8_t sensorUnitsSignedBits = 2 << 6;
    constexpr uint8_t signedDataFormat = 0x80;
    // if sensorUnits1 [7:6] = 10b, sensor is signed
    if ((sensorInfo.sensorUnits1 & sensorUnitsSignedBits) == signedDataFormat)
    {
        if (rawData > std::numeric_limits<int8_t>::max() ||
            rawData < std::numeric_limits<int8_t>::lowest())
        {
            lg2::error("Value out of range");
            throw std::out_of_range("Value out of range");
        }
        setReading(static_cast<int8_t>(rawData), &response);
    }
    else
    {
        if (rawData > std::numeric_limits<uint8_t>::max() ||
            rawData < std::numeric_limits<uint8_t>::lowest())
        {
            lg2::error("Value out of range");
            throw std::out_of_range("Value out of range");
        }
        setReading(static_cast<uint8_t>(rawData), &response);
    }

    if (!std::isfinite(value))
    {
        response.readingOrStateUnavailable = 1;
    }

    if (!sensorCacheMap[id].has_value())
    {
        sensorCacheMap[id] = SensorData{};
    }
    sensorCacheMap[id]->response = response;

    return response;
}

#endif // FEATURE_SENSORS_CACHE

} // namespace get

namespace set
{

/** @brief Make a DBus message for a Dbus call
 *  @param[in] updateInterface - Interface name
 *  @param[in] sensorPath - Path of the sensor
 *  @param[in] command - command to be executed
 *  @param[in] sensorInterface - DBus interface of sensor
 *  @return a dbus message
 */
IpmiUpdateData makeDbusMsg(const std::string& updateInterface,
                           const std::string& sensorPath,
                           const std::string& command,
                           const std::string& sensorInterface);

/** @brief Update d-bus based on assertion type sensor data
 *  @param[in] cmdData - input sensor data
 *  @param[in] sensorInfo - sensor d-bus info
 *  @return a IPMI error code
 */
ipmi_ret_t assertion(const SetSensorReadingReq& cmdData,
                     const Info& sensorInfo);

/** @brief Update d-bus based on a reading assertion
 *  @tparam T - type of d-bus property mapping this sensor
 *  @param[in] cmdData - input sensor data
 *  @param[in] sensorInfo - sensor d-bus info
 *  @return a IPMI error code
 */
template <typename T>
ipmi_ret_t readingAssertion(const SetSensorReadingReq& cmdData,
                            const Info& sensorInfo)
{
    auto msg =
        makeDbusMsg("org.freedesktop.DBus.Properties", sensorInfo.sensorPath,
                    "Set", sensorInfo.sensorInterface);

    const auto& interface = sensorInfo.propertyInterfaces.begin();
    msg.append(interface->first);
    for (const auto& property : interface->second)
    {
        msg.append(property.first);
        std::variant<T> value = static_cast<T>(
            (cmdData.assertOffset8_14 << 8) | cmdData.assertOffset0_7);
        msg.append(value);
    }
    return updateToDbus(msg);
}

/** @brief Update d-bus based on a discrete reading
 *  @param[in] cmdData - input sensor data
 *  @param[in] sensorInfo - sensor d-bus info
 *  @return an IPMI error code
 */
template <typename T>
ipmi_ret_t readingData(const SetSensorReadingReq& cmdData,
                       const Info& sensorInfo)
{
    T raw_value = (sensorInfo.coefficientM * cmdData.reading) +
                  sensorInfo.scaledOffset;

    raw_value *= std::pow(10, sensorInfo.exponentR - sensorInfo.scale);

    auto msg =
        makeDbusMsg("org.freedesktop.DBus.Properties", sensorInfo.sensorPath,
                    "Set", sensorInfo.sensorInterface);

    const auto& interface = sensorInfo.propertyInterfaces.begin();
    msg.append(interface->first);

    for (const auto& property : interface->second)
    {
        msg.append(property.first);
        std::variant<T> value = raw_value;
        msg.append(value);
    }
    return updateToDbus(msg);
}

/** @brief Update d-bus based on eventdata type sensor data
 *  @param[in] cmdData - input sensor data
 *  @param[in] sensorInfo - sensor d-bus info
 *  @return a IPMI error code
 */
ipmi_ret_t eventdata(const SetSensorReadingReq& cmdData, const Info& sensorInfo,
                     uint8_t data);

/** @brief Update d-bus based on eventdata1 type sensor data
 *  @param[in] cmdData - input sensor data
 *  @param[in] sensorInfo - sensor d-bus info
 *  @return a IPMI error code
 */
inline ipmi_ret_t eventdata1(const SetSensorReadingReq& cmdData,
                             const Info& sensorInfo)
{
    return eventdata(cmdData, sensorInfo, cmdData.eventData1);
}

/** @brief Update d-bus based on eventdata2 type sensor data
 *  @param[in] cmdData - input sensor data
 *  @param[in] sensorInfo - sensor d-bus info
 *  @return a IPMI error code
 */
inline ipmi_ret_t eventdata2(const SetSensorReadingReq& cmdData,
                             const Info& sensorInfo)
{
    return eventdata(cmdData, sensorInfo, cmdData.eventData2);
}

/** @brief Update d-bus based on eventdata3 type sensor data
 *  @param[in] cmdData - input sensor data
 *  @param[in] sensorInfo - sensor d-bus info
 *  @return a IPMI error code
 */
inline ipmi_ret_t eventdata3(const SetSensorReadingReq& cmdData,
                             const Info& sensorInfo)
{
    return eventdata(cmdData, sensorInfo, cmdData.eventData3);
}

} // namespace set

namespace notify
{

/** @brief Make a DBus message for a Dbus call
 *  @param[in] updateInterface - Interface name
 *  @param[in] sensorPath - Path of the sensor
 *  @param[in] command - command to be executed
 *  @param[in] sensorInterface - DBus interface of sensor
 *  @return a dbus message
 */
IpmiUpdateData makeDbusMsg(const std::string& updateInterface,
                           const std::string& sensorPath,
                           const std::string& command,
                           const std::string& sensorInterface);

/** @brief Update d-bus based on assertion type sensor data
 *  @param[in] interfaceMap - sensor interface
 *  @param[in] cmdData - input sensor data
 *  @param[in] sensorInfo - sensor d-bus info
 *  @return a IPMI error code
 */
ipmi_ret_t assertion(const SetSensorReadingReq& cmdData,
                     const Info& sensorInfo);

} // namespace notify

namespace inventory
{

namespace get
{

#ifndef FEATURE_SENSORS_CACHE

/**
 *  @brief Map the Dbus info to sensor's assertion status in the Get sensor
 *         reading command response.
 *
 *  @param[in] sensorInfo - Dbus info related to sensor.
 *
 *  @return Response for get sensor reading command.
 */
GetSensorResponse assertion(const Info& sensorInfo);

#else

/**
 *  @brief Map the Dbus info to sensor's assertion status in the Get sensor
 *         reading command response.
 *
 *  @param[in] id - The sensor id
 *  @param[in] sensorInfo - Dbus info related to sensor.
 *  @param[in] msg - Dbus message from match callback.
 *
 *  @return Response for get sensor reading command.
 */
std::optional<GetSensorResponse> assertion(uint8_t id, const Info& sensorInfo,
                                           const PropertyMap& properties);

#endif

} // namespace get

} // namespace inventory
} // namespace sensor
} // namespace ipmi
