#pragma once

#include <cstdint>
#include <vector>

namespace ipmi::storage
{

/** Update the FRU buffer and report whether the write reaches the end of
 *  a complete area. Incomplete areas return false for delayed write-back.
 */
bool processFruWrite(std::vector<uint8_t>& fru, uint16_t offset,
                     const std::vector<uint8_t>& data);

} // namespace ipmi::storage
