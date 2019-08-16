#pragma once

#include <ipmid/types.hpp>
#include <nlohmann/json.hpp>

ipmi::sensor::EntityInfoMap buildJsonEntityMap(const nlohmann::json& data);
