#pragma once

#include <ipmid/types.hpp>
#include <nlohmann/json.hpp>

namespace ipmi
{
namespace sensor
{

/**
 * @brief Grab a handle to the entity map.
 */
const EntityInfoMap& getIpmiEntityRecords();

/**
 * @brief Open the default entity map json file, and if present and valid json,
 * return a built entity map.
 *
 * @return the map
 */
EntityInfoMap buildEntityMapFromFile();

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
