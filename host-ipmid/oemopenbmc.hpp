#pragma once

#include <host-ipmid/ipmid-api.h>

#include <host-ipmid/oemrouter.hpp>

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
    blobTransferCmd = 128,
};

} // namespace oem
