#pragma once
#include <string>
#include <vector>

namespace ipmi
{
namespace fru
{

static constexpr uint8_t typeASCII = 0xC0;

using FruAreaData = std::vector<uint8_t>;
using Section = std::string;
using Value = std::string;
using Property = std::string;
using PropertyMap = std::map<Property, Value>;
using FruInventoryData = std::map<Section, PropertyMap>;

/**
 * @brief Builds Fru area data from inventory data
 *
 * @param[in] invData FRU properties values read from inventory
 *
 * @return FruAreaData FRU area data as per IPMI specification
 */
FruAreaData buildFruAreaData(const FruInventoryData& inventory);

} //fru
} //ipmi

