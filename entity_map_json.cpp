#include "entity_map_json.hpp"

#include <exception>
#include <ipmid/types.hpp>
#include <nlohmann/json.hpp>
#include <string>
#include <utility>

namespace ipmi
{
namespace sensor
{

EntityInfoMap buildJsonEntityMap(const nlohmann::json& data)
{
    EntityInfoMap builtMap;

    if (data.type() != nlohmann::json::value_t::array)
    {
        return builtMap;
    }

    try
    {
        for (const auto& entry : data)
        {
            /* It's an array entry with the following fields: id,
             * containerEntityId, containerEntityInstance, isList, isLinked,
             * entities[4]
             */
            EntityInfo obj;
            Id recordId = entry.at("id").get<Id>();
            obj.containerEntityId =
                entry.at("containerEntityId").get<uint8_t>();
            obj.containerEntityInstance =
                entry.at("containerEntityInstance").get<uint8_t>();
            obj.isList = entry.at("isList").get<bool>();
            obj.isLinked = entry.at("isLinked").get<bool>();

            auto jsonEntities = entry.at("entities");

            if (jsonEntities.type() != nlohmann::json::value_t::array)
            {
                throw std::runtime_error(
                    "Invalid type for entities entry, must be array");
            }
            if (jsonEntities.size() != obj.containedEntities.size())
            {
                throw std::runtime_error(
                    "Entities must be in pairs of " +
                    std::to_string(obj.containedEntities.size()));
            }

            for (std::size_t i = 0; i < obj.containedEntities.size(); i++)
            {
                obj.containedEntities[i] = std::make_pair(
                    jsonEntities[i].at("id").get<uint8_t>(),
                    jsonEntities[i].at("instance").get<uint8_t>());
            }

            builtMap.insert({recordId, obj});
        }
    }
    catch (const std::exception& e)
    {
        /* If any entry is invalid, the entire file cannot be trusted. */
        builtMap.clear();
    }

    return builtMap;
}

} // namespace sensor
} // namespace ipmi
