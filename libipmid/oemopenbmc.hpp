#pragma once

#include <libipmid/api.h>

#include <libipmid/oemrouter.hpp>

namespace oem
{
/*
 * OpenBMC OEM Extension IPMI Command codes.
 */
enum Cmd
{
    gpioCmd = 1,
    i2cCmd = 2,
    flashCmd = 3,
    fanManualCmd = 4,
    ethStatsCmd = 48,
    blobTransferCmd = 128,
};

} // namespace oem
