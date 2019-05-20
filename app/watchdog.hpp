#pragma once

#include <ipmid/api.hpp>

/** @brief The RESET watchdog IPMI command.
 */
ipmi::RspType<> ipmiAppResetWatchdogTimer();

/**@brief The setWatchdogTimer ipmi command.
 *
 * @param
 * - timerUse
 * - dontStopTimer
 * - dontLog
 * - timerAction
 * - pretimeout
 * - expireFlags
 * - initialCountdown
 *
 * @return completion code on success.
 **/
ipmi::RspType<> ipmiSetWatchdogTimer(
    uint3_t timerUse, uint3_t reserved, bool dontStopTimer, bool dontLog,
    uint3_t timeoutAction, uint1_t reserved1, uint3_t preTimeoutInterrupt,
    uint1_t reserved2, uint8_t preTimeoutInterval, uint1_t reserved3,
    uint5_t expFlagValue, uint2_t reserved4, uint16_t initialCountdown);

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
ipmi::RspType<uint8_t,  // timerUse
              uint8_t,  // timerAction
              uint8_t,  // pretimeout
              uint8_t,  // expireFlags
              uint16_t, // initial Countdown - Little Endian (deciseconds)
              uint16_t  // present Countdown - Little Endian (deciseconds)
              >
    ipmiGetWatchdogTimer();
