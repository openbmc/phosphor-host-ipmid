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
#include <cstdio>
#include <cstring>
#include <exception>
#include <filesystem>
#include <ipmid/api.hpp>
#include <ipmid/types.hpp>
#include <map>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus/match.hpp>
#include <string>
#include <vector>

#pragma once

static constexpr bool debug = false;

struct CmpStrVersion
{
    bool operator()(std::string a, std::string b) const
    {
        return strverscmp(a.c_str(), b.c_str()) < 0;
    }
};

using SensorSubTree = boost::container::flat_map<
    std::string,
    boost::container::flat_map<std::string, std::vector<std::string>>,
    CmpStrVersion>;

using SensorNumMap = boost::bimap<int, std::string>;

static constexpr uint16_t maxSensorsPerLUN = 255;
static constexpr uint16_t maxIPMISensors = (maxSensorsPerLUN * 3);
static constexpr uint16_t lun1Sensor0 = 0x100;
static constexpr uint16_t lun3Sensor0 = 0x300;
static constexpr uint16_t invalidSensorNumber = 0xFFFF;
static constexpr uint8_t reservedSensorNumber = 0xFF;

namespace details
{
bool getSensorSubtree(std::shared_ptr<SensorSubTree>& subtree);

bool getSensorNumMap(std::shared_ptr<SensorNumMap>& sensorNumMap);
} // namespace details

bool getSensorSubtree(SensorSubTree& subtree);

struct CmpStr
{
    bool operator()(const char* a, const char* b) const
    {
        return std::strcmp(a, b) < 0;
    }
};

enum class SensorTypeCodes : uint8_t
{
    reserved = 0x0,
    temperature = 0x1,
    voltage = 0x2,
    current = 0x3,
    fan = 0x4,
    other = 0xB,
};

const static boost::container::flat_map<const char*, SensorTypeCodes, CmpStr>
    sensorTypes{{{"temperature", SensorTypeCodes::temperature},
                 {"voltage", SensorTypeCodes::voltage},
                 {"current", SensorTypeCodes::current},
                 {"fan_tach", SensorTypeCodes::fan},
                 {"fan_pwm", SensorTypeCodes::fan},
                 {"power", SensorTypeCodes::other}}};

std::string getSensorTypeStringFromPath(const std::string& path);

uint8_t getSensorTypeFromPath(const std::string& path);

uint16_t getSensorNumberFromPath(const std::string& path);

uint8_t getSensorEventTypeFromPath(const std::string& path);

std::string getPathFromSensorNumber(uint16_t sensorNum);

namespace ipmi
{
std::map<std::string, std::vector<std::string>>
    getObjectInterfaces(const char* path);

std::map<std::string, Value> getEntityManagerProperties(const char* path,
                                                        const char* interface);

const std::string* getSensorConfigurationInterface(
    const std::map<std::string, std::vector<std::string>>&
        sensorInterfacesResponse);

void updateIpmiFromAssociation(const std::string& path,
                               const DbusInterfaceMap& sensorMap,
                               uint8_t& entityId, uint8_t& entityInstance);
} // namespace ipmi
