// SPDX-FileCopyrightText: Copyright OpenBMC Authors
// SPDX-License-Identifier: Apache-2.0

#include "dbus-sdr/fruwrite.hpp"

#include <algorithm>

namespace ipmi::storage
{

bool processFruWrite(std::vector<uint8_t>& fru, uint16_t fruInventoryOffset,
                     const std::vector<uint8_t>& dataToWrite)
{
    size_t writeLen = dataToWrite.size();
    size_t lastWriteAddr = fruInventoryOffset + writeLen;
    if (fru.size() < lastWriteAddr)
    {
        fru.resize(fruInventoryOffset + writeLen);
    }

    std::copy(dataToWrite.begin(), dataToWrite.begin() + writeLen,
              fru.begin() + fruInventoryOffset);

    bool atEnd = false;

    constexpr size_t commonHeaderSize = 8;
    if (fru.size() >= commonHeaderSize)
    {
        size_t areaLength = 0;
        bool completeArea = true;
        // Common header bytes 1..5 hold the internal, chassis, board,
        // product and MultiRecord offsets, in units of eight bytes.
        size_t lastRecordStart =
            std::max({fru[1], fru[2], fru[3], fru[4], fru[5]});
        lastRecordStart *= 8;

        if (fru[5])
        {
            // This FRU has a MultiRecord Area
            constexpr size_t multiRecordHeaderSize = 5;
            lastRecordStart = fru[5] * 8;
            uint8_t endOfList = 0;
            // Walk the MultiRecord headers until the last record
            while (!endOfList)
            {
                if (lastRecordStart > fru.size() ||
                    fru.size() - lastRecordStart < multiRecordHeaderSize)
                {
                    completeArea = false;
                    break;
                }
                // The MSB in the second byte of the MultiRecord header signals
                // "End of list"
                endOfList = fru[lastRecordStart + 1] & 0x80;
                // Third byte in the MultiRecord header is the length
                areaLength = fru[lastRecordStart + 2];
                // This length is in bytes (not 8 bytes like other headers)
                areaLength += multiRecordHeaderSize;
                if (areaLength > fru.size() - lastRecordStart)
                {
                    completeArea = false;
                    break;
                }
                if (!endOfList)
                {
                    // Next MultiRecord header
                    lastRecordStart += areaLength;
                }
            }
        }
        else
        {
            // This FRU does not have a MultiRecord Area
            // Get the length of the area in multiples of 8 bytes
            if (lastWriteAddr > (lastRecordStart + 1))
            {
                // second byte in record area is the length
                areaLength = fru[lastRecordStart + 1];
                areaLength *= 8; // it is in multiples of 8 bytes
            }
        }
        if (completeArea && lastWriteAddr >= (areaLength + lastRecordStart))
        {
            atEnd = true;
        }
    }
    return atEnd;
}

} // namespace ipmi::storage
