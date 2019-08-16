#include <ipmid/types.hpp>
#include <nlohmann/json.hpp>

ipmi::sensor::EntityInfoMap buildJsonEntityMap(const nlohmann::json& data)
{
    ipmi::sensor::EntityInfoMap builtMap;

    if (data.type() != nlohmann::json::value_t::array)
    {
        return builtMap;
    }

    return builtMap;
}
