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

#include "dbus-sdr/sdrutils.hpp"

#include <boost/container/flat_map.hpp>
#include <iostream>
#include <optional>
#include <sdbusplus/message/native_types.hpp>
#include <unordered_set>

#ifdef FEATURE_HYBRID_SENSORS

#include <ipmid/utils.hpp>
namespace ipmi
{
namespace sensor
{
extern const IdInfoMap sensors;
} // namespace sensor
} // namespace ipmi

#endif

namespace details
{
uint16_t getSensorSubtree(ipmi::Context::ptr ctx,
                          std::shared_ptr<SensorSubTree>& subtree)
{
    static std::shared_ptr<SensorSubTree> sensorTreePtr;
    static uint16_t sensorUpdatedIndex = 0;
    static sdbusplus::bus::match::match sensorAdded(
        *ctx->bus,
        "type='signal',member='InterfacesAdded',arg0path='/xyz/openbmc_project/"
        "sensors/'",
        [](sdbusplus::message::message&) { sensorTreePtr.reset(); });

    static sdbusplus::bus::match::match sensorRemoved(
        *ctx->bus,
        "type='signal',member='InterfacesRemoved',arg0path='/xyz/"
        "openbmc_project/sensors/'",
        [](sdbusplus::message::message&) { sensorTreePtr.reset(); });

    if (sensorTreePtr != nullptr)
    {
        subtree = sensorTreePtr;
        return sensorUpdatedIndex;
    }

    sensorTreePtr = std::make_shared<SensorSubTree>();

    static constexpr const int32_t depth = 2;

    auto lbdUpdateSensorTree = [](ipmi::Context::ptr ctx, const char* path,
                                  const auto& interfaces) {
        boost::system::error_code ec;
        SensorSubTree sensorTreePartial =
            ctx->bus->yield_method_call<SensorSubTree>(
                ctx->yield, ec, "xyz.openbmc_project.ObjectMapper",
                "/xyz/openbmc_project/object_mapper",
                "xyz.openbmc_project.ObjectMapper", "GetSubTree", path, depth,
                interfaces);

        if (ec)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "fail to update subtree",
                phosphor::logging::entry("PATH=%s", path),
                phosphor::logging::entry("WHAT=%s", ec.message().c_str()));
            return false;
        }
        if constexpr (debug)
        {
            std::fprintf(stderr, "IPMI updated: %zu sensors under %s\n",
                         sensorTreePartial.size(), path);
        }
        sensorTreePtr->merge(std::move(sensorTreePartial));
        return true;
    };

    // Add sensors to SensorTree
    static constexpr const std::array sensorInterfaces = {
        "xyz.openbmc_project.Sensor.Value",
        "xyz.openbmc_project.Sensor.ValueMutability",
        "xyz.openbmc_project.Sensor.Threshold.Warning",
        "xyz.openbmc_project.Sensor.Threshold.Critical"};
    static constexpr const std::array vrInterfaces = {
        "xyz.openbmc_project.Control.VoltageRegulatorMode"};

    bool sensorRez = lbdUpdateSensorTree(ctx, "/xyz/openbmc_project/sensors",
                                         sensorInterfaces);

#ifdef FEATURE_HYBRID_SENSORS

    for (const auto& sensor : ipmi::sensor::sensors)
    {
        // Threshold sensors should not be emplaced in here.
        if (sensor.second.sensorPath.starts_with(
                "/xyz/openbmc_project/sensors/"))
        {
            continue;
        }

        // The bus service name is not listed in ipmi::sensor::Info. Give it
        // an empty string. For those function using non-threshold sensors,
        // the bus service name will be retrieved in an alternative way.
        boost::container::flat_map<std::string, std::vector<std::string>>
            connectionMap{
                {"", {sensor.second.propertyInterfaces.begin()->first}}};
        sensorTreePtr->emplace(sensor.second.sensorPath, connectionMap);
    }

#endif

    // Error if searching for sensors failed.
    if (!sensorRez)
    {
        return sensorUpdatedIndex;
    }

    // Add VR control as optional search path.
    (void)lbdUpdateSensorTree(ctx, "/xyz/openbmc_project/vr", vrInterfaces);

    subtree = sensorTreePtr;
    sensorUpdatedIndex++;
    // The SDR is being regenerated, wipe the old stats
    sdrStatsTable.wipeTable();
    sdrWriteTable.wipeTable();
    return sensorUpdatedIndex;
}

bool getSensorNumMap(ipmi::Context::ptr ctx,
                     std::shared_ptr<SensorNumMap>& sensorNumMap)
{
    static std::shared_ptr<SensorNumMap> sensorNumMapPtr;
    bool sensorNumMapUpated = false;
    static uint16_t prevSensorUpdatedIndex = 0;
    std::shared_ptr<SensorSubTree> sensorTree;
    uint16_t curSensorUpdatedIndex = details::getSensorSubtree(ctx, sensorTree);
    if (!sensorTree)
    {
        return sensorNumMapUpated;
    }

    if ((curSensorUpdatedIndex == prevSensorUpdatedIndex) && sensorNumMapPtr)
    {
        sensorNumMap = sensorNumMapPtr;
        return sensorNumMapUpated;
    }
    prevSensorUpdatedIndex = curSensorUpdatedIndex;

    sensorNumMapPtr = std::make_shared<SensorNumMap>();

    uint16_t sensorNum = 0;
    uint16_t sensorIndex = 0;
    for (const auto& sensor : *sensorTree)
    {
        sensorNumMapPtr->insert(
            SensorNumMap::value_type(sensorNum, sensor.first));
        sensorIndex++;
        if (sensorIndex == maxSensorsPerLUN)
        {
            sensorIndex = lun1Sensor0;
        }
        else if (sensorIndex == (lun1Sensor0 | maxSensorsPerLUN))
        {
            // Skip assigning LUN 0x2 any sensors
            sensorIndex = lun3Sensor0;
        }
        else if (sensorIndex == (lun3Sensor0 | maxSensorsPerLUN))
        {
            // this is an error, too many IPMI sensors
            throw std::out_of_range("Maximum number of IPMI sensors exceeded.");
        }
        sensorNum = sensorIndex;
    }
    sensorNumMap = sensorNumMapPtr;
    sensorNumMapUpated = true;
    return sensorNumMapUpated;
}
} // namespace details

bool getSensorSubtree(ipmi::Context::ptr ctx, SensorSubTree& subtree)
{
    std::shared_ptr<SensorSubTree> sensorTree;
    details::getSensorSubtree(ctx, sensorTree);
    if (!sensorTree)
    {
        return false;
    }

    subtree = *sensorTree;
    return true;
}

#ifdef FEATURE_HYBRID_SENSORS
// Static sensors are listed in sensor-gen.cpp.
ipmi::sensor::IdInfoMap::const_iterator
    findStaticSensor(const std::string& path)
{
    return std::find_if(
        ipmi::sensor::sensors.begin(), ipmi::sensor::sensors.end(),
        [&path](const ipmi::sensor::IdInfoMap::value_type& findSensor) {
            return findSensor.second.sensorPath == path;
        });
}
#endif

std::optional<std::string>
    getSensorTypeStringFromPath(const sdbusplus::message::object_path& path)
{
    // get sensor type string from path, path is defined as
    // /xyz/openbmc_project/sensors/<type>/label
    const sdbusplus::message::object_path& typePath = path.parent_path();
    const std::string typeStr = typePath.filename();

    if (typeStr.empty())
    {
        return std::nullopt;
    }

    return typeStr;
}

uint8_t getSensorTypeFromPath(const std::string& path)
{
    const std::optional<std::string>& typeStr =
        getSensorTypeStringFromPath(path);
    if (typeStr == std::nullopt)
    {
        return 0;
    }

    auto findSensor = sensorTypes.find(typeStr->c_str());
    if (findSensor != sensorTypes.end())
    {
        return static_cast<uint8_t>(
            std::get<sensorTypeCodes>(findSensor->second));
    } // else default 0x0 RESERVED

    return 0;
}

uint16_t getSensorNumberFromPath(ipmi::Context::ptr ctx,
                                 const std::string& path)
{
    std::shared_ptr<SensorNumMap> sensorNumMapPtr;
    details::getSensorNumMap(ctx, sensorNumMapPtr);
    if (!sensorNumMapPtr)
    {
        return invalidSensorNumber;
    }

    try
    {
        return sensorNumMapPtr->right.at(path);
    }
    catch (const std::out_of_range& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return invalidSensorNumber;
    }
}

uint8_t getSensorEventTypeFromPath(const std::string& path)
{
    const std::optional<std::string>& typeStr =
        getSensorTypeStringFromPath(path);
    if (typeStr == std::nullopt)
    {
        return 0;
    }

    auto findSensor = sensorTypes.find(typeStr->c_str());
    if (findSensor != sensorTypes.end())
    {
        return static_cast<uint8_t>(
            std::get<sensorEventTypeCodes>(findSensor->second));
    }

    return 0;
}

std::string getPathFromSensorNumber(ipmi::Context::ptr ctx, uint16_t sensorNum)
{
    std::shared_ptr<SensorNumMap> sensorNumMapPtr;
    details::getSensorNumMap(ctx, sensorNumMapPtr);
    if (!sensorNumMapPtr)
    {
        return std::string();
    }

    try
    {
        return sensorNumMapPtr->left.at(sensorNum);
    }
    catch (const std::out_of_range& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return std::string();
    }
}

namespace ipmi
{

boost::container::flat_map<std::string, std::vector<std::string>>
    getObjectInterfaces(ipmi::Context::ptr ctx, const char* path)
{
    boost::system::error_code ec;
    auto interfacesResponse = ctx->bus->yield_method_call<
        boost::container::flat_map<std::string, std::vector<std::string>>>(
        ctx->yield, ec, "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetObject", path,
        std::vector<std::string>{});

    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to GetObject", phosphor::logging::entry("PATH=%s", path),
            phosphor::logging::entry("WHAT=%s", ec.message().c_str()));
    }

    return interfacesResponse;
}

boost::container::flat_map<std::string, Value>
    getEntityManagerProperties(ipmi::Context::ptr ctx, const char* path,
                               const char* interface)
{
    boost::system::error_code ec;
    auto properties =
        ctx->bus
            ->yield_method_call<boost::container::flat_map<std::string, Value>>(
                ctx->yield, ec, "xyz.openbmc_project.EntityManager", path,
                "org.freedesktop.DBus.Properties", "GetAll", interface);

    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to GetAll", phosphor::logging::entry("PATH=%s", path),
            phosphor::logging::entry("INTF=%s", interface),
            phosphor::logging::entry("WHAT=%s", ec.message().c_str()));
    }

    return properties;
}

const std::string* getSensorConfigurationInterface(
    const boost::container::flat_map<std::string, std::vector<std::string>>&
        sensorInterfacesResponse)
{
    auto entityManagerService =
        sensorInterfacesResponse.find("xyz.openbmc_project.EntityManager");
    if (entityManagerService == sensorInterfacesResponse.end())
    {
        return nullptr;
    }

    // Find the fan configuration first (fans can have multiple configuration
    // interfaces).
    for (const auto& entry : entityManagerService->second)
    {
        if (entry == "xyz.openbmc_project.Configuration.AspeedFan" ||
            entry == "xyz.openbmc_project.Configuration.I2CFan" ||
            entry == "xyz.openbmc_project.Configuration.NuvotonFan")
        {
            return &entry;
        }
    }

    for (const auto& entry : entityManagerService->second)
    {
        if (entry.starts_with("xyz.openbmc_project.Configuration."))
        {
            return &entry;
        }
    }

    return nullptr;
}

// Follow Association properties for Sensor back to the Board dbus object to
// check for an EntityId and EntityInstance property.
void updateIpmiFromAssociation(ipmi::Context::ptr ctx, const std::string& path,
                               const DbusInterfaceMap& sensorMap,
                               uint8_t& entityId, uint8_t& entityInstance)
{
    namespace fs = std::filesystem;

    auto sensorAssociationObject =
        sensorMap.find("xyz.openbmc_project.Association.Definitions");
    if (sensorAssociationObject == sensorMap.end())
    {
        if constexpr (debug)
        {
            std::fprintf(stderr, "path=%s, no association interface found\n",
                         path.c_str());
        }

        return;
    }

    auto associationObject =
        sensorAssociationObject->second.find("Associations");
    if (associationObject == sensorAssociationObject->second.end())
    {
        if constexpr (debug)
        {
            std::fprintf(stderr, "path=%s, no association records found\n",
                         path.c_str());
        }

        return;
    }

    std::vector<Association> associationValues =
        std::get<std::vector<Association>>(associationObject->second);

    // loop through the Associations looking for the right one:
    for (const auto& entry : associationValues)
    {
        // forward, reverse, endpoint
        const std::string& forward = std::get<0>(entry);
        const std::string& reverse = std::get<1>(entry);
        const std::string& endpoint = std::get<2>(entry);

        // We only currently concern ourselves with chassis+all_sensors.
        if (!(forward == "chassis" && reverse == "all_sensors"))
        {
            continue;
        }

        // the endpoint is the board entry provided by
        // Entity-Manager. so let's grab its properties if it has
        // the right interface.

        // just try grabbing the properties first.
        boost::container::flat_map<std::string, Value> ipmiProperties =
            getEntityManagerProperties(
                ctx, endpoint.c_str(),
                "xyz.openbmc_project.Inventory.Decorator.Ipmi");

        auto entityIdProp = ipmiProperties.find("EntityId");
        auto entityInstanceProp = ipmiProperties.find("EntityInstance");
        if (entityIdProp != ipmiProperties.end())
        {
            entityId =
                static_cast<uint8_t>(std::get<uint64_t>(entityIdProp->second));
        }
        if (entityInstanceProp != ipmiProperties.end())
        {
            entityInstance = static_cast<uint8_t>(
                std::get<uint64_t>(entityInstanceProp->second));
        }

        // Now check the entity-manager entry for this sensor to see
        // if it has its own value and use that instead.
        //
        // In theory, checking this first saves us from checking
        // both, except in most use-cases identified, there won't be
        // a per sensor override, so we need to always check both.
        std::string sensorNameFromPath = fs::path(path).filename();

        std::string sensorConfigPath = endpoint + "/" + sensorNameFromPath;

        // Download the interfaces for the sensor from
        // Entity-Manager to find the name of the configuration
        // interface.
        boost::container::flat_map<std::string, std::vector<std::string>>
            sensorInterfacesResponse =
                getObjectInterfaces(ctx, sensorConfigPath.c_str());

        const std::string* configurationInterface =
            getSensorConfigurationInterface(sensorInterfacesResponse);

        // We didnt' find a configuration interface for this sensor, but we
        // followed the Association property to get here, so we're done
        // searching.
        if (!configurationInterface)
        {
            break;
        }

        // We found a configuration interface.
        boost::container::flat_map<std::string, Value> configurationProperties =
            getEntityManagerProperties(ctx, sensorConfigPath.c_str(),
                                       configurationInterface->c_str());

        entityIdProp = configurationProperties.find("EntityId");
        entityInstanceProp = configurationProperties.find("EntityInstance");
        if (entityIdProp != configurationProperties.end())
        {
            entityId =
                static_cast<uint8_t>(std::get<uint64_t>(entityIdProp->second));
        }
        if (entityInstanceProp != configurationProperties.end())
        {
            entityInstance = static_cast<uint8_t>(
                std::get<uint64_t>(entityInstanceProp->second));
        }

        // stop searching Association records.
        break;
    } // end for Association vectors.

    if constexpr (debug)
    {
        std::fprintf(stderr, "path=%s, entityId=%d, entityInstance=%d\n",
                     path.c_str(), entityId, entityInstance);
    }
}

} // namespace ipmi
