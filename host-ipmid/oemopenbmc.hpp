#pragma once

#include "host-ipmid/ipmid-api.h"
#include "host-ipmid/oemrouter.hpp"

namespace ipmid
{
namespace oem
{
namespace openbmc
{

/*
 * This is the OpenBMC IANA OEM Number
 */
constexpr OemNumber obmcOemNumber = 49871;

/*
 * OpenBMC OEM Extension IPMI Command codes.
 */
enum OemCmd : ipmi_cmd_t
{
    gpioCmd = 1,
    i2cCmd = 2,
    flashCmd = 3,
    fanManualCmd = 4,
};

}  // namespace openbmc
}  // namespace oem
}  // namespace ipmid
