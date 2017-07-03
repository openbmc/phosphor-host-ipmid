#pragma once
#include <string>
#include <sdbusplus/bus.hpp>
#include "ipmi_fru_info_area.hpp"

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
FruAreaData& getFruAreaData(const FRUId& fruNum);

} //fru
} //ipmi
