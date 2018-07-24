#pragma once

#include "host-ipmid/oemrouter.hpp"

namespace oem
{
constexpr Number googOemNumber = 11129;

/* Google OEM commands. */
enum GoogOemCmd
{
    ethStatsCmd = 48,
    gsysCmd = 50,
    nemoraSettingsCmd = 52,
    flashOverBTCmd = 127,
    blobTransferCmd = 128,
};

}  // namespace oem

