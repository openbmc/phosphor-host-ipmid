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

#include "sensordatahandler.hpp"

#include <ipmid/utils.hpp>

constexpr std::array<const char*, 7> suffixes = {
    "_Output_Voltage", "_Input_Voltage", "_Output_Current", "_Input_Current",
    "_Output_Power",   "_Input_Power",   "_Temperature"};

namespace ipmi
{
namespace sensor
{
#ifdef FEATURE_HYBRID_SENSORS
extern const IdInfoMap sensors;
#endif

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
        // try to not truncate by replacing common words
        for (const auto& suffix : suffixes)
        {
            if (boost::ends_with(name, suffix))
            {
                boost::replace_all(name, suffix, "");
                break;
            }
        }
        if (name.size() > FULL_RECORD_ID_STR_MAX_LENGTH)
        {
            name.resize(FULL_RECORD_ID_STR_MAX_LENGTH);
        }
    }
    std::replace(name.begin(), name.end(), '_', ' ');
    return name;
}

} // namespace sensor
} // namespace ipmi

namespace details
{
uint16_t getSensorSubtree(std::shared_ptr<SensorSubTree>& subtree)
{
    static std::shared_ptr<SensorSubTree> sensorTreePtr;
    static uint16_t sensorUpdatedIndex = 0;
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    static sdbusplus::bus::match_t sensorAdded(
        *dbus,
        "type='signal',member='InterfacesAdded',arg0path='/xyz/openbmc_project/"
        "sensors/'",
        [](sdbusplus::message_t&) { sensorTreePtr.reset(); });

    static sdbusplus::bus::match_t sensorRemoved(
        *dbus,
        "type='signal',member='InterfacesRemoved',arg0path='/xyz/"
        "openbmc_project/sensors/'",
        [](sdbusplus::message_t&) { sensorTreePtr.reset(); });

    static sdbusplus::bus::match_t inventoryAdded(
        *dbus,
        "type='signal',member='InterfacesRemoved',arg0path='/xyz/"
        "openbmc_project/inventory/'",
        [](sdbusplus::message_t&) { sensorTreePtr.reset(); });

    static sdbusplus::bus::match_t inventoryRemoved(
        *dbus,
        "type='signal',member='InterfacesRemoved',arg0path='/xyz/"
        "openbmc_project/inventory/'",
        [](sdbusplus::message_t&) { sensorTreePtr.reset(); });

    if (sensorTreePtr)
    {
        subtree = sensorTreePtr;
        return sensorUpdatedIndex;
    }

    sensorTreePtr = std::make_shared<SensorSubTree>();

    static constexpr const int32_t depth = 2;

    auto lbdUpdateSensorTree = [&dbus](const char* path, const auto& interfaces,
                                       const bool groupByObjPath = false) {
        auto mapperCall = dbus->new_method_call(
            "xyz.openbmc_project.ObjectMapper",
            "/xyz/openbmc_project/object_mapper",
            "xyz.openbmc_project.ObjectMapper", "GetSubTree");
        SensorSubTree sensorTreePartial;

        mapperCall.append(path, depth, interfaces);

        try
        {
            auto mapperReply = dbus->call(mapperCall);
            mapperReply.read(sensorTreePartial);
        }
        catch (const sdbusplus::exception_t& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "fail to update subtree",
                phosphor::logging::entry("PATH=%s", path),
                phosphor::logging::entry("WHAT=%s", e.what()));
            return false;
        }
        if constexpr (debug)
        {
            std::fprintf(stderr, "IPMI updated: %zu sensors under %s\n",
                         sensorTreePartial.size(), path);
        }

        if (groupByObjPath)
        {
            static constexpr int discreteSensorMaxState = 14;
            // Merging the object with similar sdrName into one discrete sensor.
            // For example, cablePresence1 and cablePresence2 should be merged.
            SensorSubTree discreteSensorTreePartial;
            // Define the distance of two objects as the index difference of
            // objectPath. Therefore, we can at most walk 14 distance away in
            // one sdr.
            while (sensorTreePartial.size())
            {
                auto head = sensorTreePartial.begin();
                // Split the index postion from the object path.
                // For example, if the object path is /xyz/cable13,
                // the index is 13.
                auto lastNotDigit = head->first.find_last_not_of("0123456789");
                if (lastNotDigit == head->first.size() - 1)
                {
                    // not indexed object path
                    discreteSensorTreePartial[head->first] = head->second;
                    sensorTreePartial.erase(head);
                    continue;
                }
                // Make a copy of the interfaces information because we will
                // erase the entries in sensorTree later.
                auto intf = head->second;
                auto indexPos = lastNotDigit + 1;
                // The default object path without the index position
                // information.
                std::string defaultObjPath = head->first.substr(0, indexPos);
                std::string sdrName =
                    ::ipmi::sensor::parseSdrIdFromPath(defaultObjPath);
                int index = std::stoi(head->first.substr(indexPos));
                int range = index;
                // Increment 1 distance on each loop.
                for (; range < discreteSensorMaxState + index; ++range)
                {
                    std::string objPath =
                        defaultObjPath + std::to_string(range);
                    if (auto it = sensorTreePartial.find(objPath);
                        it != sensorTreePartial.end())
                    {
                        sensorTreePartial.erase(it);
                    }
                    else
                    {
                        break;
                    }
                }
                // Construct the ranged object path. e.g. /xyz/cable[1-3].
                std::string rangedObjPath;
                // we don't want cdfp[0-0].
                if (range - 1 != index) {
                  rangedObjPath = defaultObjPath + "[" +
                      std::to_string(index) + "-" +
                      std::to_string(--range) + "]";
                } else {
                  rangedObjPath = defaultObjPath + std::to_string(index);
                }
                discreteSensorTreePartial[rangedObjPath] = intf;
            }
            sensorTreePtr->merge(std::move(discreteSensorTreePartial));
        }
        else
        {
            sensorTreePtr->merge(std::move(sensorTreePartial));
        }
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
    static constexpr const std::array discreteCableInterface = {
        "xyz.openbmc_project.Inventory.Item.Cable"};

    bool sensorRez =
        lbdUpdateSensorTree("/xyz/openbmc_project/sensors", sensorInterfaces);

#ifdef FEATURE_HYBRID_SENSORS

    if (!ipmi::sensor::sensors.empty())
    {
        for (const auto& sensor : ipmi::sensor::sensors)
        {
            // Threshold sensors should not be emplaced in here.
            if (boost::starts_with(sensor.second.sensorPath,
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
    }

#endif

    // Error if searching for sensors failed.
    if (!sensorRez)
    {
        return sensorUpdatedIndex;
    }

    // Add VR control as optional search path.
    (void)lbdUpdateSensorTree("/xyz/openbmc_project/vr", vrInterfaces);

    (void)lbdUpdateSensorTree("/xyz/openbmc_project/inventory/system",
                              discreteCableInterface,
                              /*groupByObjPath=*/true);

    subtree = sensorTreePtr;
    sensorUpdatedIndex++;
    // The SDR is being regenerated, wipe the old stats
    sdrStatsTable.wipeTable();
    sdrWriteTable.wipeTable();
    return sensorUpdatedIndex;
}

bool getSensorNumMap(std::shared_ptr<SensorNumMap>& sensorNumMap)
{
    static std::shared_ptr<SensorNumMap> sensorNumMapPtr;
    bool sensorNumMapUpated = false;
    static uint16_t prevSensorUpdatedIndex = 0;
    std::shared_ptr<SensorSubTree> sensorTree;
    uint16_t curSensorUpdatedIndex = details::getSensorSubtree(sensorTree);
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

bool getSensorSubtree(SensorSubTree& subtree)
{
    std::shared_ptr<SensorSubTree> sensorTree;
    details::getSensorSubtree(sensorTree);
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

std::string getSensorTypeStringFromPath(const std::string& path)
{
    // get sensor type string from path, path is defined as
    // /xyz/openbmc_project/sensors/<type>/label
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

uint8_t getSensorTypeFromPath(const std::string& path)
{
    uint8_t sensorType = 0;
    std::string type = getSensorTypeStringFromPath(path);
    auto findSensor = sensorTypes.find(type.c_str());
    if (findSensor != sensorTypes.end())
    {
        sensorType =
            static_cast<uint8_t>(std::get<sensorTypeCodes>(findSensor->second));
    } // else default 0x0 RESERVED

    return sensorType;
}

uint16_t getSensorNumberFromPath(const std::string& path)
{
    std::shared_ptr<SensorNumMap> sensorNumMapPtr;
    details::getSensorNumMap(sensorNumMapPtr);
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
    uint8_t sensorEventType = 0;
    std::string type = getSensorTypeStringFromPath(path);
    auto findSensor = sensorTypes.find(type.c_str());
    if (findSensor != sensorTypes.end())
    {
        sensorEventType = static_cast<uint8_t>(
            std::get<sensorEventTypeCodes>(findSensor->second));
    }

    return sensorEventType;
}

std::string getPathFromSensorNumber(uint16_t sensorNum)
{
    std::shared_ptr<SensorNumMap> sensorNumMapPtr;
    details::getSensorNumMap(sensorNumMapPtr);
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

std::map<std::string, std::vector<std::string>>
    getObjectInterfaces(const char* path)
{
    std::map<std::string, std::vector<std::string>> interfacesResponse;
    std::vector<std::string> interfaces;
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();

    sdbusplus::message_t getObjectMessage =
        dbus->new_method_call("xyz.openbmc_project.ObjectMapper",
                              "/xyz/openbmc_project/object_mapper",
                              "xyz.openbmc_project.ObjectMapper", "GetObject");
    getObjectMessage.append(path, interfaces);

    try
    {
        sdbusplus::message_t response = dbus->call(getObjectMessage);
        response.read(interfacesResponse);
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to GetObject", phosphor::logging::entry("PATH=%s", path),
            phosphor::logging::entry("WHAT=%s", e.what()));
    }

    return interfacesResponse;
}

std::map<std::string, Value> getEntityManagerProperties(const char* path,
                                                        const char* interface)
{
    std::map<std::string, Value> properties;
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();

    sdbusplus::message_t getProperties =
        dbus->new_method_call("xyz.openbmc_project.EntityManager", path,
                              "org.freedesktop.DBus.Properties", "GetAll");
    getProperties.append(interface);

    try
    {
        sdbusplus::message_t response = dbus->call(getProperties);
        response.read(properties);
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to GetAll", phosphor::logging::entry("PATH=%s", path),
            phosphor::logging::entry("INTF=%s", interface),
            phosphor::logging::entry("WHAT=%s", e.what()));
    }

    return properties;
}

const std::string* getSensorConfigurationInterface(
    const std::map<std::string, std::vector<std::string>>&
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
        if (boost::algorithm::starts_with(entry,
                                          "xyz.openbmc_project.Configuration."))
        {
            return &entry;
        }
    }

    return nullptr;
}

// Follow Association properties for Sensor back to the Board dbus object to
// check for an EntityId and EntityInstance property.
void updateIpmiFromAssociation(const std::string& path,
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
        std::map<std::string, Value> ipmiProperties =
            getEntityManagerProperties(
                endpoint.c_str(),
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
        std::map<std::string, std::vector<std::string>>
            sensorInterfacesResponse =
                getObjectInterfaces(sensorConfigPath.c_str());

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
        std::map<std::string, Value> configurationProperties =
            getEntityManagerProperties(sensorConfigPath.c_str(),
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
