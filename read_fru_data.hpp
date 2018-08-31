#pragma once
#include "ipmi_fru_info_area.hpp"

#include <sdbusplus/bus.hpp>
#include <string>

namespace ipmi
{
namespace fru
{
using FRUId = uint8_t;
using FRUAreaMap = std::map<FRUId, FruAreaData>;
/**
 * @brief Get fru area data as per IPMI specification
 *
 * @param[in] fruNum FRU ID
 *
 * @return FRU area data as per IPMI specification
 */
const FruAreaData& getFruAreaData(const FRUId& fruNum);

/**
 * @brief Register callback handler into DBUS for PropertyChange events
 *
 * @return negative value on failure
 */
int registerCallbackHandler();
} // namespace fru
} // namespace ipmi
