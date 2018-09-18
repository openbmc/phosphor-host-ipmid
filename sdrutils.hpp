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
#include <boost/container/flat_map.hpp>
#include <phosphor-logging/log.hpp>

#include "sensorhandler.h"

#pragma once
using GetSubTreeType = std::vector<
    std::pair<std::string,
              std::vector<std::pair<std::string, std::vector<std::string>>>>>;

inline static bool GetSensorSubtree(GetSubTreeType& subtree, bool& updated)
{
    sd_bus* bus = NULL;
    int ret = sd_bus_default_system(&bus);
    if (ret < 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to connect to system bus",
            phosphor::logging::entry("ERRNO=0x%X", -ret));
        sd_bus_unref(bus);
        return false;
    }
    sdbusplus::bus::bus dbus(bus);
    auto subtreeCopy = subtree;
    auto mapperCall =
        dbus.new_method_call("xyz.openbmc_project.ObjectMapper",
                             "/xyz/openbmc_project/object_mapper",
                             "xyz.openbmc_project.ObjectMapper", "GetSubTree");
    static const auto depth = 2;
    static constexpr std::array<const char*, 3> interfaces = {
        "xyz.openbmc_project.Sensor.Value",
        "xyz.openbmc_project.Sensor.Threshold.Warning",
        "xyz.openbmc_project.Sensor.Threshold.Critical"};
    mapperCall.append("/xyz/openbmc_project/sensors", depth, interfaces);

    try
    {
        auto mapperReply = dbus.call(mapperCall);
        subtree.clear();
        mapperReply.read(subtree);
    }
    catch (sdbusplus::exception_t&)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "GetSensorSubtree: Error calling mapper");
        return false;
    }

    // sort by sensor path
    std::sort(subtree.begin(), subtree.end(), [](auto& left, auto& right) {
        return boost::ilexicographical_compare<std::string, std::string>(
            left.first, right.first);
    });
    updated = false;
    if (subtreeCopy.empty())
    {
        updated = true;
    }
    else if (subtreeCopy.size() != subtree.size())
    {
        updated = true;
    }
    else
    {
        for (int ii = 0; ii < static_cast<int>(subtreeCopy.size()); ii++)
        {
            // if the path or the connection has changed
            if (subtreeCopy[ii] != subtree[ii])
            {
                updated = true;
                break;
            }
        }
    }
    return true;
}

struct cmp_str
{
    bool operator()(const char* a, const char* b) const
    {
        return std::strcmp(a, b) < 0;
    }
};

const static boost::container::flat_map<const char*, ipmi_sensor_types, cmp_str>
    SENSOR_TYPES{{{"temperature", IPMI_SENSOR_TEMP},
                  {"voltage", IPMI_SENSOR_VOLTAGE},
                  {"current", IPMI_SENSOR_CURRENT},
                  {"fan_tach", IPMI_SENSOR_FAN},
                  {"power", IPMI_SENSOR_OTHER}}};

inline static std::string GetSensorTypeStringFromPath(const std::string& path)
{
    // get sensor type string from path, path is defined as
    // /xyz/openbmc_project/sensors/<type>/label
    std::string type = path;
    auto lastSlash = type.rfind(std::string("/"));
    // delete everything after last slash inclusive
    if (lastSlash != std::string::npos)
    {
        type.erase(lastSlash);
    }
    // delete everything before new last slash inclusive
    lastSlash = type.rfind(std::string("/"));
    if (lastSlash != std::string::npos)
    {
        type.erase(0, lastSlash + 1);
    }
    return type;
}

inline static uint8_t GetSensorTypeFromPath(const std::string& path)
{
    uint8_t sensorType = 0;
    std::string type = GetSensorTypeStringFromPath(path);
    auto findSensor = SENSOR_TYPES.find(type.c_str());
    if (findSensor != SENSOR_TYPES.end())
    {
        sensorType = findSensor->second;
    } // else default 0x0 RESERVED

    return sensorType;
}

inline static uint8_t GetSensorNumberFromPath(const std::string& path)
{
    GetSubTreeType sensorTree;
    bool updated = false;
    if (!GetSensorSubtree(sensorTree, updated))
        return 0xFF;

    for (int i = 0; i < static_cast<int>(sensorTree.size()); i++)
    {
        if (sensorTree[i].first == path)
        {
            return i;
        }
    }
    return 0xFF;
}

inline static uint8_t GetSensorEventTypeFromPath(const std::string& path)
{
    return 0x1; // reading type = threshold
}

inline static std::string GetPathFromSensorNumber(uint8_t sensorNum)
{
    GetSubTreeType sensorTree;
    bool updated = false;
    if (!GetSensorSubtree(sensorTree, updated))
        return std::string();

    if (sensorTree.size() < sensorNum)
    {
        return std::string();
    }

    return sensorTree[sensorNum].first;
}
