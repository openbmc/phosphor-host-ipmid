#pragma once
#include <string>
#include <sdbusplus/bus.hpp>
#include "ipmi_fru_info_area.hpp"

namespace ipmi
{
namespace fru
{
using FrusAreaMap = std::map<uint8_t, FruAreaData>;
/**
 * @brief Get fru area data as per IPMI specification
 *
 * @param[in] bus - dbus
 * @param[in] fruNum FRU number
 * @return FRU area data as per IPMI specification
 */
FruAreaData getFruAreaData(sdbusplus::bus::bus& bus, const uint8_t& fruNum);

/**
 * @brief Register for fru value change notification 
 *
 * @return negative value on failure
 */
int registerFruPropertyChangeHandle();
} //fru
} //ipmi
