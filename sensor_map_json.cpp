#include "sensor_map_json.hpp"

#include <ipmid/types.hpp>
#include <nlohmann/json.hpp>

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
        else
        {}
    }
}

} // namespace sensor
} // namespace ipmi
