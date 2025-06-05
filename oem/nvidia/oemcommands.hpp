#pragma once
#include <cstdint>

namespace ipmi
{

using Group = uint8_t;
constexpr Group groupNvidia = 0x3C;

namespace bios_password
{
constexpr auto cmdSetBiosPassword = 0x36;
constexpr auto cmdGetBiosPassword = 0x37;
} // namespace bios_password
} // namespace ipmi
