#include "sensor_map_json.hpp"

#include "sensordatahandler.hpp"

#include <ipmid/types.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>

namespace fs = std::filesystem;

namespace ipmi
{
namespace sensor
{
#ifndef FEATURE_SENSORS_CACHE
using GetFuncMaps =
    std::map<std::string, std::function<GetSensorResponse(const Info&)>>;
#else
using GetFuncMaps =
    std::map<std::string, std::function<std::optional<GetSensorResponse>(
                              uint8_t, const Info&, const ipmi::PropertyMap&)>>;
#endif

using UpdateFuncMaps =
    std::map<std::string,
             std::function<uint8_t(SetSensorReadingReq&, const Info&)>>;

const UpdateFuncMaps updateFuncMaps = {
    {"notify::assertion", notify::assertion},
    {"set::eventdata2", set::eventdata2},
    {"set::assertion", set::assertion},
    {"set::readingData<bool>", set::readingData<bool>},
    {"set::readingData<uint8_t>", set::readingData<uint8_t>},
    {"set::readingData<int16_t>", set::readingData<int16_t>},
    {"set::readingData<uint16_t>", set::readingData<uint16_t>},
    {"set::readingData<int32_t>", set::readingData<int32_t>},
    {"set::readingData<uint32_t>", set::readingData<uint32_t>},
    {"set::readingData<int64_t>", set::readingData<int64_t>},
    {"set::readingData<uint64_t>", set::readingData<uint64_t>},
    {"set::readingData<double>", set::readingData<double>},
    {"set::readingAssertion<bool>", set::readingAssertion<bool>},
    {"set::readingAssertion<uint8_t>", set::readingAssertion<uint8_t>},
    {"set::readingAssertion<int16_t>", set::readingAssertion<int16_t>},
    {"set::readingAssertion<uint16_t>", set::readingAssertion<uint16_t>},
    {"set::readingAssertion<int32_t>", set::readingAssertion<int32_t>},
    {"set::readingAssertion<uint32_t>", set::readingAssertion<uint32_t>},
    {"set::readingAssertion<int64_t>", set::readingAssertion<int64_t>},
    {"set::readingAssertion<uint64_t>", set::readingAssertion<uint64_t>},
    {"set::readingAssertion<double>", set::readingAssertion<double>}};

const GetFuncMaps getFuncMaps = {
    {"get::assertion", get::assertion},
    {"get::eventdata2", get::eventdata2},
    {"get::readingData<uint8_t>", get::readingData<uint8_t>},
    {"get::readingData<int16_t>", get::readingData<int16_t>},
    {"get::readingData<uint16_t>", get::readingData<uint16_t>},
    {"get::readingData<int32_t>", get::readingData<int32_t>},
    {"get::readingData<uint32_t>", get::readingData<uint32_t>},
    {"get::readingData<int64_t>", get::readingData<int64_t>},
    {"get::readingData<uint64_t>", get::readingData<uint64_t>},
    {"get::readingData<double>", get::readingData<double>},
    {"get::readingAssertion<bool>", get::readingAssertion<bool>},
    {"get::readingAssertion<uint8_t>", get::readingAssertion<uint8_t>},
    {"get::readingAssertion<int16_t>", get::readingAssertion<int16_t>},
    {"get::readingAssertion<uint16_t>", get::readingAssertion<uint16_t>},
    {"get::readingAssertion<int32_t>", get::readingAssertion<int32_t>},
    {"get::readingAssertion<uint32_t>", get::readingAssertion<uint32_t>},
    {"get::readingAssertion<int64_t>", get::readingAssertion<int64_t>},
    {"get::readingAssertion<uint64_t>", get::readingAssertion<uint64_t>},
    {"get::readingAssertion<double>", get::readingAssertion<double>}};

SensorMapContainer* SensorMapContainer::getContainer()
{
    static std::unique_ptr<SensorMapContainer> instance;

    if (!instance)
    {
        instance =
            std::unique_ptr<SensorMapContainer>(new SensorMapContainer());
    }

    return instance.get();
}

const InvObjectIDMap& SensorMapContainer::getInvSensors()
{
    return invSensors;
}

const IdInfoMap& SensorMapContainer::getIdInfoSensors()
{
    return idInfoSensors;
}

void SensorMapContainer::loadInvSensors(const nlohmann::json& invJson)
{
    if (!invJson.is_object())
    {
        return;
    }
    const nlohmann::json empty{};
    for (const auto& [path, selJson] : invJson.items())
    {
        SelData selData;
        selData.sensorID = selJson.value("sensorID", 0);
        selData.sensorType = selJson.value("sensorType", 0);
        selData.eventReadingType = selJson.value("eventReadingType", 0);
        selData.eventOffset = selJson.value("eventOffset", 0);
        invSensors.emplace(path, selData);
    }
}

bool SensorMapContainer::isContains(const nlohmann::json& arrayJson,
                                    const std::string& name)
{
    if (!arrayJson.is_array())
    {
        return false;
    }

    std::string tmpName = name;
    for (const auto& value : arrayJson)
    {
        std::string tmpValue = value;
        std::transform(tmpValue.begin(), tmpValue.end(), tmpValue.begin(),
                       tolower);
        std::transform(tmpName.begin(), tmpName.end(), tmpName.begin(),
                       ::tolower);
        if (tmpValue == tmpName)
        {
            return true;
        }
    }

    return false;
}

void SensorMapContainer::loadIdInfoSensors(const nlohmann::json& idInfoJson)
{
    if (!idInfoJson.is_array())
    {
        return;
    }

    const nlohmann::json empty{};
    for (const auto& entryJson : idInfoJson)
    {
        Id id = entryJson.value("id", 0);
        auto instancesJson = entryJson.value("instances", empty);

        Info info;
        info.entityType = instancesJson.value("entityType", 0);
        info.instance = instancesJson.value("entityInstance", 0);
        info.sensorType = instancesJson.value("sensorType", 0);
        info.sensorPath = instancesJson.value("path", "");
        info.sensorInterface = instancesJson.value("serviceInterface", "");
        info.sensorReadingType = instancesJson.value("sensorReadingType", 0);
        info.coefficientM = instancesJson.value("multiplierM", 0x1);
        info.coefficientB = instancesJson.value("offsetB", 0);
        info.exponentB = instancesJson.value("bExp", 0);
        info.scaledOffset = info.coefficientB * pow(10, info.exponentB);
        info.exponentR = instancesJson.value("rExp", 0);
        auto scale = instancesJson.value("scale", empty);
        info.hasScale = false;
        if (!scale.empty())
        {
            info.scale = scale;
            info.hasScale = true;
        }
        info.sensorUnits1 = instancesJson.value("sensorUnits1", 0);
        info.unit = instancesJson.value("unit", "");
        info.sensorName = instancesJson.value(
            "sensorName",
            sdbusplus::message::object_path(info.sensorPath).filename());

        std::string updateFunc{};
        std::string getFunc{};
        if (info.sensorInterface == "org.freedesktop.DBus.Properties")
        {
            updateFunc = "set::";
            getFunc = "get::";
        }
        else if (info.sensorInterface ==
                 "xyz.openbmc_project.Inventory.Manager")
        {
            updateFunc = "notify::";
            getFunc = "inventory::get::";
        }
        else
        {
            std::cerr << "Un-supported interface: " << info.sensorInterface
                      << std::endl;
            continue;
        }

        std::string valueType{};
        auto interfacesJson = instancesJson.value("interfaces", empty);
        if (!interfacesJson.is_object())
        {
            continue;
        }

        for (const auto& [interface, properties] : interfacesJson.items())
        {
            DbusPropertyMap dbusPropertyMap;
            for (const auto& [property, values] : properties.items())
            {
                PreReqOffsetValueMap preOffsetMap;
                OffsetValueMap offsetMap;
                if (values.find("Offsets") != values.end())
                {
                    for (const auto& valueJson : values["Offsets"])
                    {
                        Offset offset = valueJson.value("offset", 0);
                        Values values;
                        valueType = valueJson.value("type", "");
                        if (offset != 255)
                        {
                            values.skip = SkipAssertion::NONE;
                            std::string skip = valueJson.value("skipOn", empty);
                            if (skip == "assert")
                            {
                                values.skip = SkipAssertion::ASSERT;
                            }
                            else if (skip == "deassert")
                            {
                                values.skip = SkipAssertion::DEASSERT;
                            }

                            auto assert = valueJson.value("assert", empty);
                            if (!assert.empty() && valueType == "string")
                            {
                                values.assert =
                                    static_cast<std::string>(assert);
                            }
                            else if (!assert.empty() && valueType == "bool")
                            {
                                values.assert = static_cast<bool>(assert);
                            }

                            auto deassert = valueJson.value("deassert", empty);
                            if (!deassert.empty())
                            {
                                values.deassert = static_cast<bool>(deassert);
                            }
                        }
                        offsetMap.emplace(offset, values);
                    }
                }
                else if (values.find("Prereqs") != values.end())
                {
                    for (const auto& valueJson : values["Prereqs"])
                    {
                        Offset offset = valueJson.value("offset", 0);
                        PreReqValues preReqValues;
                        std::string type = valueJson.value("type", "");
                        if (type == "bool")
                        {
                            preReqValues.assert = valueJson.value("assert",
                                                                  false);
                            preReqValues.deassert = valueJson.value("deassert",
                                                                    false);
                        }
                        preOffsetMap.emplace(offset, preReqValues);
                    }
                }
                dbusPropertyMap.emplace(
                    property, std::make_pair(preOffsetMap, offsetMap));
            }
            info.propertyInterfaces.emplace(interface, dbusPropertyMap);
        }

        std::string valueReadingType = instancesJson.value("readingType", "");
        if ("readingAssertion" == valueReadingType ||
            "readingData" == valueReadingType)
        {
            updateFunc = "set::" + valueReadingType + "<" + valueType + ">";
            getFunc = "get::" + valueReadingType + "<" + valueType + ">";
        }

        if (info.sensorInterface == "org.freedesktop.DBus.Properties" &&
            !info.propertyInterfaces.empty())
        {
            info.sensorInterface = info.propertyInterfaces.begin()->first;
        }
        info.sensorNameFunc = nullptr;
        auto mutabilityArray = instancesJson.value("mutability", empty);
        if (isContains(mutabilityArray, "write") &&
            isContains(mutabilityArray, "read"))
        {
            info.mutability = Mutability(Mutability::Write | Mutability::Read);
        }
        else if (isContains(mutabilityArray, "write"))
        {
            info.mutability = Mutability(Mutability::Write);
        }
        else
        {
            info.mutability = Mutability(Mutability::Read);
        }

        auto updateFuncIter = updateFuncMaps.find(updateFunc);
        if (updateFuncIter != updateFuncMaps.end())
        {
            info.updateFunc = updateFuncIter->second;
        }

        auto getFuncIter = getFuncMaps.find(getFunc);
        if (getFuncIter != getFuncMaps.end())
        {
            info.getFunc = getFuncIter->second;
        }

        idInfoSensors.emplace(id, info);
    }
}

void SensorMapContainer::loadConfigurations()
{
    std::string sensorPaths = "/usr/share/ipmi-providers/";
    for (const auto& p : fs::directory_iterator(sensorPaths))
    {
        if (p.path().extension() != ".json")
        {
            std::cerr << "Invaild sensor configuration file: " << p.path()
                      << "\n";
            continue;
        }

        std::ifstream mapFile(p.path());
        if (!mapFile.is_open())
        {
            return;
        }

        auto data = nlohmann::json::parse(mapFile, nullptr, false);
        if (data.is_discarded())
        {
            return;
        }

        if (data.find("InventorySensors") != data.end())
        {
            loadInvSensors(data["InventorySensors"]);
        }
        else if (data.find("IdInfoSensors") != data.end())
        {
            loadIdInfoSensors(data["IdInfoSensors"]);
        }
        else
        {}
    }
}

} // namespace sensor
} // namespace ipmi
