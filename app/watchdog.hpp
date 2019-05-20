#pragma once

#include <ipmid/api.hpp>

/** @brief The RESET watchdog IPMI command.
 */
ipmi::RspType<> ipmiAppResetWatchdogTimer();

//@brief The Set watchdog ipmi command.
ipmi::RspType<> ipmiSetWatchdog(uint8_t timerUse, uint8_t timerAction,
                                uint8_t pretimeout, uint8_t expireFlags,
                                uint16_t initialCountdown);

//@brief The Get watchdog ipmi command.
ipmi::RspType<uint8_t, uint8_t, uint8_t, uint8_t,
              uint16_t, // Little Endian (deciseconds)
              uint16_t  // Little Endian (deciseconds)
              >
    ipmiGetWatchdog();
