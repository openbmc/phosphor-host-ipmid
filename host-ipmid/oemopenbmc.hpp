#pragma once

#include "host-ipmid/oemrouter.hpp"

#include "host-ipmid/ipmid-api.h"

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
};

} // namespace oem
