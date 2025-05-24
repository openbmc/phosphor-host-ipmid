#pragma once

#include "comm_module.hpp"

#include <sdbusplus/bus/match.hpp>

#include <cstddef>
#include <vector>

namespace command
{

constexpr size_t BMC_GUID_LEN = 16;

using Guid = std::array<uint8_t, BMC_GUID_LEN>;

/**
 * @brief Get System GUID
 *
 * @return If UUID is successfully read from the Chassis DBUS object, then the
 *         GUID is returned, else a canned GUID is returned
 */
const Guid& getSystemGUID();

/**
 *  @brief Register the callback to update the cache when the GUID changes
 */
void registerGUIDChangeCallback();

} // namespace command
