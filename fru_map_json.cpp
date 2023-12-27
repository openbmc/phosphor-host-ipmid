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
        else
        {}
    }
}

} // namespace fru
} // namespace ipmi
