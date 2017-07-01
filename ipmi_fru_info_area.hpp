#pragma once
#include <string>
#include <vector>

namespace phosphor
{
namespace hostipmi
{
using FruAreaData = std::vector<uint8_t>;
using Section = std::string;
using Value = std::string;
using Property = std::string;
using FruInventoryData = std::vector<std::tuple<Section, Property, Value>>;

/**
 * @brief Builds Fru area data from inventory data
 *
 * @param[in] invData inventory data
 * @return fruArea FRU area date as per IPMI specification
 */
FruAreaData buildFruAreaData(const FruInventoryData& invData);

} //hostipmi
} //phosphor

