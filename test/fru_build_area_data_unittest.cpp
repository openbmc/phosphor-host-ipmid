#include "ipmi_fru_info_area.hpp"

#include <iomanip>
#include <sstream>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace ipmi
{
namespace fru
{

FruAreaData buildProductInfoArea(const PropertyMap&);
FruAreaData buildChassisInfoArea(const PropertyMap&);
FruAreaData buildBoardInfoArea(const PropertyMap&);

// This returns the fruData formatted as hexadecimal bytes,
// space separated, e.g.
// 01 02 00 c0 c0 c0 00 c0 00 00 00 c1 00 00 00 3c
std::string formatFruArea(const FruAreaData& fruData)
{
    std::stringstream result;
    for (unsigned byte : fruData)
    {
        result << std::setfill('0') << std::setw(2) << std::hex << byte << " ";
    }

    return result.str();
}

TEST(BuildArea, EmptyMapEmptyArea)
{
    PropertyMap empty_map;
    auto data = buildProductInfoArea(empty_map);
    EXPECT_EQ(data.size(), 0);

    data = buildChassisInfoArea(empty_map);
    EXPECT_EQ(data.size(), 0);

    data = buildBoardInfoArea(empty_map);
    EXPECT_EQ(data.size(), 0);

    for (const auto& prop_name :
         {"Serial Number", "Manufacturer", "Mfg Date", "Model Number", "Name"})
    {
        empty_map.emplace(prop_name, "");
    }

    data = buildProductInfoArea(empty_map);
    EXPECT_EQ(data.size(), 0) << formatFruArea(data);

    data = buildChassisInfoArea(empty_map);
    EXPECT_EQ(data.size(), 0) << formatFruArea(data);

    data = buildBoardInfoArea(empty_map);
    EXPECT_EQ(data.size(), 0) << formatFruArea(data);
}

} // namespace fru
} // namespace ipmi
