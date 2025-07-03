#pragma once

#include <stdint.h>

#include <cstddef>

// IPMI Command for a Net Function number as specified by IPMI V2.0 spec.
using Cmd = uint8_t;

// ipmi function return the status code
using Cc = uint8_t;

// Command specific completion codes
constexpr Cc ccParmNotSupported = 0xCD;
constexpr Cc failSetInProgress = 0x81;

// Various Chassis operations under a single command.
constexpr Cmd cmdPowerOff = 0x00;
constexpr Cmd cmdPowerOn = 0x01;
constexpr Cmd cmdPowerCycle = 0x02;
constexpr Cmd cmdHardReset = 0x03;
constexpr Cmd cmdPulseDiagnosticInterrupt = 0x04;
constexpr Cmd cmdSoftOffViaOverTemp = 0x05;

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
