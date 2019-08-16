#pragma once

#include <ipmid/types.hpp>
#include <nlohmann/json.hpp>

namespace ipmi
{
namespace sensor
{

/**
 * @brief Given json data validate the data matches the expected format for the
 * entity map configuration and parse the data into a map of the entities.
 *
 * If any entry is invalid, the entire contents passed in is disregarded as
 * possibly corrupt.
 *
 * @param[in] data - the json data
 * @return the map
 */
EntityInfoMap buildJsonEntityMap(const nlohmann::json& data);

} // namespace sensor
} // namespace ipmi
