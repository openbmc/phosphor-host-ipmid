#pragma once

#include "host-ipmid/ipmid-api.h"
#include "host-ipmid/oemrouter.hpp"

namespace oem
{

/*
 * This is the OpenBMC IANA OEM Number
 */
constexpr Number obmcOemNumber = 49871;

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

}  // namespace oem
