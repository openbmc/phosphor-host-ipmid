#pragma once

#include <ipmid/api.hpp>

/** @brief The RESET watchdog IPMI command.
 */
ipmi::RspType<> ipmiAppResetWatchdogTimer();

/**@brief The setWatchdogTimer ipmi command.
 *
 * @param
 * - timerUse
 * - stopOnSet
 * - shouldLog
 * - timerAction
 * - pretimeout
 * - expireFlags
 * - initialCountdown
 *
 * @return completion code on success.
 **/
ipmi::RspType<> ipmiSetWatchdogTimer(uint3_t timerUse, uint3_t reserved,
                                     uint1_t stopOnSet, uint1_t shouldLog,
                                     uint8_t timerAction, uint8_t pretimeout,
                                     uint8_t expireFlags,
                                     uint16_t initialCountdown);

/**@brief The getWatchdogTimer ipmi command.
 *
 * @return
 * - timerUse
 * - timerActions
 * - pretimeout
 * - timeruseFlags
 * - initialCountdown
 * - presentCountdown
 **/
ipmi::RspType<uint8_t, uint8_t, uint8_t, uint8_t,
              uint16_t, // Little Endian (deciseconds)
              uint16_t  // Little Endian (deciseconds)
              >
    ipmiGetWatchdogTimer();
