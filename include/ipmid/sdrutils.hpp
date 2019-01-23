/*
// Copyright (c) 2018 Intel Corporation
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

#include <boost/algorithm/string.hpp>
#include <boost/bimap.hpp>
#include <boost/container/flat_map.hpp>
#include <cstring>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus/match.hpp>

#pragma once

using namespace phosphor::logging;

// Discrete sensor types.
enum ipmi_sensor_types
{
    IPMI_SENSOR_TEMP = 0x01,
    IPMI_SENSOR_VOLTAGE = 0x02,
    IPMI_SENSOR_CURRENT = 0x03,
    IPMI_SENSOR_FAN = 0x04,
    IPMI_SENSOR_OTHER = 0x0B,
    IPMI_SENSOR_TPM = 0xCC,
};

struct CmpStrVersion
{
    bool operator()(std::string a, std::string b) const
    {
        return strverscmp(a.c_str(), b.c_str()) < 0;
    }
};

// GetSubTree returns a map where the key is a D-Bus path and the value is
// another map where the key is the D-Bus service name and the value is an array
// of interfaces implemented on the D-Bus path
using SensorSubTree = boost::container::flat_map<
    std::string,
    boost::container::flat_map<std::string, std::vector<std::string>>,
    CmpStrVersion>;

using SensorNumMap = boost::bimap<int, std::string>;

namespace sensor_details
{
inline static bool getSensorSubtree(std::shared_ptr<SensorSubTree>& subtree)
{
    static std::shared_ptr<SensorSubTree> sensorTreePtr;
    sdbusplus::bus::bus dbus = sdbusplus::bus::new_default_system();
    static sdbusplus::bus::match::match sensorAdded(
        dbus,
        "type='signal',member='InterfacesAdded',arg0path='/xyz/openbmc_project/"
        "sensors/'",
        [](sdbusplus::message::message& m) { sensorTreePtr.reset(); });

    static sdbusplus::bus::match::match sensorRemoved(
        dbus,
        "type='signal',member='InterfacesRemoved',arg0path='/xyz/"
        "openbmc_project/sensors/'",
        [](sdbusplus::message::message& m) { sensorTreePtr.reset(); });

    bool sensorTreeUpdated = false;
    if (sensorTreePtr)
    {
        subtree = sensorTreePtr;
        return sensorTreeUpdated;
    }

    sensorTreePtr = std::make_shared<SensorSubTree>();

    auto mapperCall =
        dbus.new_method_call("xyz.openbmc_project.ObjectMapper",
                             "/xyz/openbmc_project/object_mapper",
                             "xyz.openbmc_project.ObjectMapper", "GetSubTree");
    static constexpr const auto depth = 2;
    static constexpr std::array<const char*, 3> interfaces = {
        "xyz.openbmc_project.Sensor.Value",
        "xyz.openbmc_project.Sensor.Threshold.Warning",
        "xyz.openbmc_project.Sensor.Threshold.Critical"};
    mapperCall.append("/xyz/openbmc_project/sensors", depth, interfaces);

    try
    {
        auto mapperReply = dbus.call(mapperCall);
        mapperReply.read(*sensorTreePtr);
    }
    catch (sdbusplus::exception_t& e)
    {
        log<level::ERR>(e.what());
        return sensorTreeUpdated;
    }
    subtree = sensorTreePtr;
    sensorTreeUpdated = true;
    return sensorTreeUpdated;
}

inline static bool getSensorNumMap(std::shared_ptr<SensorNumMap>& sensorNumMap)
{
    static std::shared_ptr<SensorNumMap> sensorNumMapPtr;
    bool sensorNumMapUpated = false;

    std::shared_ptr<SensorSubTree> sensorTree;
    bool sensorTreeUpdated = getSensorSubtree(sensorTree);
    if (!sensorTree)
    {
        return sensorNumMapUpated;
    }

    if (!sensorTreeUpdated && sensorNumMapPtr)
    {
        sensorNumMap = sensorNumMapPtr;
        return sensorNumMapUpated;
    }

    sensorNumMapPtr = std::make_shared<SensorNumMap>();

    uint8_t sensorNum = 1;
    for (const auto& sensor : *sensorTree)
    {
        sensorNumMapPtr->insert(
            SensorNumMap::value_type(sensorNum++, sensor.first));
    }
    sensorNumMap = sensorNumMapPtr;
    sensorNumMapUpated = true;
    return sensorNumMapUpated;
}
} // namespace sensor_details

inline static bool getSensorSubtree(SensorSubTree& subtree)
{
    std::shared_ptr<SensorSubTree> sensorTree;
    sensor_details::getSensorSubtree(sensorTree);
    if (!sensorTree)
    {
        return false;
    }

    subtree = *sensorTree;
    return true;
}

struct CmpStr
{
    bool operator()(const char* a, const char* b) const
    {
        return std::strcmp(a, b) < 0;
    }
};

const static boost::container::flat_map<const char*, ipmi_sensor_types, CmpStr>
    sensorTypes{{{"temperature", IPMI_SENSOR_TEMP},
                 {"voltage", IPMI_SENSOR_VOLTAGE},
                 {"current", IPMI_SENSOR_CURRENT},
                 {"fan_tach", IPMI_SENSOR_FAN},
                 {"fan_pwm", IPMI_SENSOR_FAN},
                 {"power", IPMI_SENSOR_OTHER}}};

inline static std::string getSensorTypeStringFromPath(const std::string& path)
{
    // get sensor type string from path, path is defined as
    // /xyz/openbmc_project/**/<type>/label
    size_t typeEnd = path.rfind("/");
    if (typeEnd == std::string::npos)
    {
        return path;
    }
    size_t typeStart = path.rfind("/", typeEnd - 1);
    if (typeStart == std::string::npos)
    {
        return path;
    }
    // Start at the character after the '/'
    typeStart++;
    return path.substr(typeStart, typeEnd - typeStart);
}

inline static uint8_t getSensorTypeFromPath(const std::string& path)
{
    uint8_t sensorType = 0;
    std::string type = getSensorTypeStringFromPath(path);
    auto findSensor = sensorTypes.find(type.c_str());
    if (findSensor != sensorTypes.end())
    {
        sensorType = findSensor->second;
    } // else default 0x0 RESERVED

    return sensorType;
}

inline static uint8_t getSensorNumberFromPath(const std::string& path)
{
    std::shared_ptr<SensorNumMap> sensorNumMapPtr;
    sensor_details::getSensorNumMap(sensorNumMapPtr);
    if (!sensorNumMapPtr)
    {
        return 0xFF;
    }

    try
    {
        return sensorNumMapPtr->right.at(path);
    }
    catch (std::out_of_range& e)
    {
        log<level::ERR>(e.what());
        return 0xFF;
    }
}

inline static uint8_t getSensorEventTypeFromPath(const std::string& path)
{
    // TODO: Add support for additional reading types as needed
    return 0x1; // reading type = threshold
}

inline static std::string getPathFromSensorNumber(uint8_t sensorNum)
{
    std::shared_ptr<SensorNumMap> sensorNumMapPtr;
    sensor_details::getSensorNumMap(sensorNumMapPtr);
    if (!sensorNumMapPtr)
    {
        return std::string();
    }

    try
    {
        return sensorNumMapPtr->left.at(sensorNum);
    }
    catch (std::out_of_range& e)
    {
        log<level::ERR>(e.what());
        return std::string();
    }
}
