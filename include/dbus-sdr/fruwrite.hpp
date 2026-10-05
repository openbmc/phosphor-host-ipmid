#pragma once

#include <cstdint>
#include <vector>

#pragma pack(push, 1)
struct FRUHeader
{
    uint8_t commonHeaderFormat;
    uint8_t internalOffset;
    uint8_t chassisOffset;
    uint8_t boardOffset;
    uint8_t productOffset;
    uint8_t multiRecordOffset;
    uint8_t pad;
    uint8_t checksum;
};
#pragma pack(pop)

namespace ipmi::storage
{

/** Update the FRU buffer and report whether the write reaches the end of
 *  a complete area. Incomplete areas return false for delayed write-back.
 */
bool processFruWrite(std::vector<uint8_t>& fru, uint16_t offset,
                     const std::vector<uint8_t>& data);

} // namespace ipmi::storage
