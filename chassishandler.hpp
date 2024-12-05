#pragma once

#include <stdint.h>

#include <cstddef>

// Command specific completion codes
enum ipmi_chassis_return_codes
{
    IPMI_OK = 0x0,
    IPMI_CC_PARM_NOT_SUPPORTED = 0x80,
    IPMI_CC_FAIL_SET_IN_PROGRESS = 0x81,
};

// Generic completion codes,
// see IPMI doc section 5.2
enum ipmi_generic_return_codes
{
    IPMI_OUT_OF_SPACE = 0xC4,
};

// Various Chassis operations under a single command.
enum ipmi_chassis_control_cmds : uint8_t
{
    CMD_POWER_OFF = 0x00,
    CMD_POWER_ON = 0x01,
    CMD_POWER_CYCLE = 0x02,
    CMD_HARD_RESET = 0x03,
    CMD_PULSE_DIAGNOSTIC_INTR = 0x04,
    CMD_SOFT_OFF_VIA_OVER_TEMP = 0x05,
};
enum class BootOptionParameter : size_t
{
    setInProgress = 0x0,
    bootFlagValidClr = 0x3,
    bootInfo = 0x4,
    bootFlags = 0x5,
    opalNetworkSettings = 0x61
};

enum class BootOptionResponseSize : size_t
{
    setInProgress = 3,
    bootFlags = 5,
    opalNetworkSettings = 50
};

enum class ChassisIDState : uint8_t
{
    off = 0x0,
    temporaryOn = 0x1,
    indefiniteOn = 0x2,
    reserved = 0x3
};
