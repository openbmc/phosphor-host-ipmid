#include <ipmid/fru_map_json.hpp>
#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>

namespace ipmi
{
namespace fru
{
namespace fs = std::filesystem;

FruMapContainer* FruMapContainer::getContainer()
{
    static std::unique_ptr<FruMapContainer> instance;

    if (!instance)
    {
        instance = std::unique_ptr<FruMapContainer>(new FruMapContainer());
    }

    return instance.get();
}

const FruMap& FruMapContainer::getFruMap()
{
    return frus;
}

const ExtrasMap& FruMapContainer::getFruExtras()
{
    return extras;
}

void FruMapContainer::loadFruMap(const nlohmann::json& fruJson)
{
    if (!fruJson.is_array())
    {
        return;
    }

    const nlohmann::json empty{};
    for (const auto& fru : fruJson)
    {
        FruId fruId = fru.value("Id", 0);
        FruInstanceVec fruInstanceVec;
        auto instancesJson = fru.value("Instances", empty);
        if (instancesJson.is_null())
        {
            continue;
        }

        for (const auto& [path, entity] : instancesJson.items())
        {
            FruInstance fruInstance;
            fruInstance.path = path;
            fruInstance.entityID = entity.value("EntityID", 0);
            fruInstance.entityInstance = entity.value("EntityInstance", 0);

            auto interfacesJson = entity.value("Interfaces", empty);
            if (interfacesJson.is_null())
            {
                continue;
            }

            for (const auto& [interface, properties] : interfacesJson.items())
            {
                DbusPropertyVec dbusPropertyVec;
                for (const auto& [property, fruData] : properties.items())
                {
                    IPMIFruData ipmiFruData;
                    ipmiFruData.section = fruData.value("IPMIFruSection", "");
                    ipmiFruData.property = fruData.value("IPMIFruProperty", "");
                    ipmiFruData.delimiter =
                        fruData.value("IPMIFruValueDelimiter", "");

                    dbusPropertyVec.push_back({property, ipmiFruData});
                }
                fruInstance.interfaces.push_back({interface, dbusPropertyVec});
            }
            fruInstanceVec.push_back(fruInstance);
        }
        frus.emplace(fruId, fruInstanceVec);
    }
}

Value FruMapContainer::jsonEntryToDbusVal(const std::string& type,
                                          const nlohmann::json& value)
{
    Value propValue{};
    if (type == "uint8_t")
    {
        propValue = static_cast<uint8_t>(value);
    }
    else if (type == "uint16_t")
    {
        propValue = static_cast<uint16_t>(value);
    }
    else if (type == "uint32_t")
    {
        propValue = static_cast<uint32_t>(value);
    }
    else if (type == "uint64_t")
    {
        propValue = static_cast<uint64_t>(value);
    }
    else if (type == "int16_t")
    {
        propValue = static_cast<int16_t>(value);
    }
    else if (type == "int32_t")
    {
        propValue = static_cast<int32_t>(value);
    }
    else if (type == "int64_t")
    {
        propValue = static_cast<int64_t>(value);
    }
    else if (type == "bool")
    {
        propValue = static_cast<bool>(value);
    }
    else if (type == "double")
    {
        propValue = static_cast<double>(value);
    }
    else if (type == "string")
    {
        propValue = static_cast<std::string>(value);
    }
    else
    {
        std::cerr << "Unknown D-Bus property type, TYPE=" << type << "\n";
    }

    return propValue;
}

void FruMapContainer::loadFruExtras(const nlohmann::json& extrasJson)
{
    if (!extrasJson.is_object())
    {
        return;
    }

    const nlohmann::json empty{};
    for (const auto& [path, interfaces] : extrasJson.items())
    {
        DbusInterfaceMap intfMap;
        for (const auto& [interface, properties] : interfaces.items())
        {
            PropertyMap propertyMap;
            for (const auto& [property, values] : properties.items())
            {
                std::string type = values.value("type", "");
                auto elem = values.value("value", empty);
                Value value = jsonEntryToDbusVal(type, elem);
                propertyMap.emplace(property, value);
            }
            intfMap.emplace(interface, propertyMap);
        }
        extras.emplace(path, intfMap);
    }
}

void FruMapContainer::loadConfigurations()
{
    std::string fruPaths = "/usr/share/ipmi-providers/";
    for (const auto& p : fs::directory_iterator(fruPaths))
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

        if (data.find("Frus") != data.end())
        {
            loadFruMap(data["Frus"]);
        }
        else if (data.find("Extras") != data.end())
        {
            loadFruExtras(data["Extras"]);
        }
        else
        {}
    }
}

} // namespace fru
} // namespace ipmi
