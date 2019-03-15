/*
 * Copyright © 2018 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#pragma once

#define ALLOW_DEPRECATED_API 1

#include <ipmid/iana.hpp>
#include <ipmid/message/types.hpp>
#include <optional>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>

/* NOTE:
 *
 * This is intended for native C++ use. For the legacy C api, include
 * ipmid-api.h for a reduced functionality. Note that the C api is now marked
 * as deprecated and will be removed once all the internal users of it have
 * been updated to use the new C++ api.
 */

namespace ipmi
{

using Iana = oem::Number;

using Group = uint8_t;
constexpr Group groupPICMG = 0x00;
constexpr Group groupDMTG = 0x01;
constexpr Group groupSSI = 0x02;
constexpr Group groupVSO = 0x03;
constexpr Group groupDCMI = 0xDC;

/*
 * Set the priority as the lowest number that is necessary so
 * it is possible that others can override it if desired.
 * This may be linked to what level of integration the handler
 * is being created at.
 */
constexpr int prioOpenBmcBase = 10;
constexpr int prioOemBase = 20;
constexpr int prioOdmBase = 30;
constexpr int prioCustomBase = 40;
constexpr int prioMax = 50;

/*
 * Channel IDs pulled from the IPMI 2.0 specification
 */
constexpr int channelPrimaryIpmb = 0x00;
// 0x01-0x0B Implementation specific
// Implementation specific channel numbers are specified
// by a configuration file external to ipmid
// 0x0C-0x0D reserved
constexpr int channelCurrentIface = 0x0E; // 'Present I/F'
constexpr int channelSystemIface = 0x0F;

/*
 * Specifies the minimum privilege level required to execute the command
 * This means the command can be executed at a given privilege level or higher
 * privilege level. Those commands which can be executed via system interface
 * only should use SYSTEM_INTERFACE
 */
enum class Privilege : uint8_t
{
    None = 0x00,
    Callback,
    User,
    Operator,
    Admin,
    Oem,
};

// IPMI Net Function number as specified by IPMI V2.0 spec.
using NetFn = uint8_t;

// IPMI Command for a Net Function number as specified by IPMI V2.0 spec.
using Cmd = uint8_t;

// ipmi function return the status code
using Cc = uint8_t;

// These are the command network functions, the response
// network functions are the function + 1. So to determine
// the proper network function which issued the command
// associated with a response, subtract 1.
// Note: these will be left shifted when combined with the LUN
constexpr NetFn netFnChassis = 0x00;
constexpr NetFn netFnBridge = 0x02;
constexpr NetFn netFnSensor = 0x04;
constexpr NetFn netFnApp = 0x06;
constexpr NetFn netFnFirmware = 0x08;
constexpr NetFn netFnStorage = 0x0A;
constexpr NetFn netFnTransport = 0x0C;
// reserved 0Eh..28h
constexpr NetFn netFnGroup = 0x2C;
constexpr NetFn netFnOem = 0x2E;
constexpr NetFn netFnOemOne = 0x30;
constexpr NetFn netFnOemTwo = 0x32;
constexpr NetFn netFnOemThree = 0x34;
constexpr NetFn netFnOemFour = 0x36;
constexpr NetFn netFnOemFive = 0x38;
constexpr NetFn netFnOemSix = 0x3A;
constexpr NetFn netFnOemSeven = 0x3C;
constexpr NetFn netFnOemEight = 0x3E;

// IPMI commands for net functions. Callbacks using this should be careful to
// parse arguments to the sub-functions and can take advantage of the built-in
// message handling mechanism to create custom routing
constexpr Cmd cmdWildcard = 0xFF;

// IPMI standard completion codes specified by the IPMI V2.0 spec.
//
// This might have been an enum class, but that would make it hard for
// OEM- and command-specific completion codes to be added elsewhere.
//
// Custom completion codes can be defined in individual modules for
// command specific errors in the 0x80-0xBE range
//
// Alternately, OEM completion codes are in the 0x01-0x7E range
constexpr Cc ccSuccess = 0x00;
constexpr Cc ccBusy = 0xC0;
constexpr Cc ccInvalidCommand = 0xC1;
constexpr Cc ccInvalidCommandOnLun = 0xC2;
constexpr Cc ccTimeout = 0xC2;
constexpr Cc ccOutOfSpace = 0xC2;
constexpr Cc ccInvalidReservationId = 0xC5;
constexpr Cc ccReqDataTruncated = 0xC6;
constexpr Cc ccReqDataLenInvalid = 0xC7;
constexpr Cc ccReqDataLenExceeded = 0xC8;
constexpr Cc ccParmOutOfRange = 0xC9;
constexpr Cc ccRetBytesUnavailable = 0xCA;
constexpr Cc ccSensorInvalid = 0xCB;
constexpr Cc ccInvalidFieldRequest = 0xCC;
constexpr Cc ccIllegalCommand = 0xCD;
constexpr Cc ccResponseError = 0xCE;
constexpr Cc ccDuplicateRequest = 0xCF;
constexpr Cc ccCmdFailSdrMode = 0xD0;
constexpr Cc ccCmdFailFwUpdMode = 0xD1;
constexpr Cc ccCmdFailInitAgent = 0xD2;
constexpr Cc ccDestinationUnavailable = 0xD3;
constexpr Cc ccInsufficientPrivilege = 0xD4;
constexpr Cc ccCommandNotAvailable = 0xD5;
constexpr Cc ccCommandDisabled = 0xD6;
constexpr Cc ccUnspecifiedError = 0xFF;

/* ipmi often has two return types:
 * 1. Failure: CC is non-zero; no trailing data
 * 2. Success: CC is zero; trailing data (usually a fixed type)
 *
 * using ipmi::response(cc, ...), it will automatically always pack
 * the correct type for the response without having to explicitly type out all
 * the parameters that the function would return.
 *
 * To enable this feature, you just define the ipmi function as returning an
 * ipmi::RspType which has the optional trailing data built in, with your types
 * defined as parameters.
 */

template <typename... RetTypes>
using RspType = std::tuple<ipmi::Cc, std::optional<std::tuple<RetTypes...>>>;

/**
 * @brief helper function to create an IPMI response tuple
 *
 * IPMI handlers all return a tuple with two parts: a completion code and an
 * optional tuple containing the rest of the data to return. This helper
 * function makes it easier by constructing that out of an arbitrary number of
 * arguments.
 *
 * @param cc - the completion code for the response
 * @param args... - the optional list of values to return
 *
 * @return a standard IPMI return type (as described above)
 */
template <typename... Args>
static inline auto response(ipmi::Cc cc, Args&&... args)
{
    return std::make_tuple(cc, std::make_optional(std::make_tuple(args...)));
}
static inline auto response(ipmi::Cc cc)
{
    return std::make_tuple(cc, std::nullopt);
}

/**
 * @brief helper function to create an IPMI success response tuple
 *
 * IPMI handlers all return a tuple with two parts: a completion code and an
 * optional tuple containing the rest of the data to return. This helper
 * function makes it easier by constructing that out of an arbitrary number of
 * arguments. Because it is a success response, this automatically packs
 * the completion code, without needing to explicitly pass it in.
 *
 * @param args... - the optional list of values to return
 *
 * @return a standard IPMI return type (as described above)
 */
template <typename... Args>
static inline auto responseSuccess(Args&&... args)
{
    return std::make_tuple(ipmi::ccSuccess,
                           std::make_optional(std::make_tuple(args...)));
}
static inline auto responseSuccess()
{
    return std::make_tuple(ipmi::ccSuccess, std::nullopt);
}

} // namespace ipmi

// any client can interact with the main asio context
std::shared_ptr<boost::asio::io_context> getIoContext();

// any client can interact with the main sdbus
std::shared_ptr<sdbusplus::asio::connection> getSdBus();

/**
 * @brief post some work to the async exection queue
 *
 * The IPMI daemon runs an async exection queue; this allows any function to
 * pass in work to be executed in that context
 *
 * @tparam WorkFn - a function of type void(void)
 * @param work - the callback function to be executed
 */
template <typename WorkFn>
static inline void post_work(WorkFn work)
{
    getIoContext()->post(std::forward<WorkFn>(work));
}

enum class SignalResponse : int
{
    breakExecution,
    continueExecution,
};

/**
 * @brief add a signal handler
 *
 * This registers a handler to be called asynchronously via the execution
 * queue when the specified signal is received.
 *
 * Priority allows a signal handler to specify what order in the handler
 * chain it gets called. Lower priority numbers will cause the handler to
 * be executed later in the chain, while the highest priority numbers will cause
 * the handler to be executed first.
 *
 * In order to facilitate a chain of handlers, each handler in the chain will be
 * able to return breakExecution or continueExecution. Returning breakExecution
 * will break the chain and no further handlers will execute for that signal.
 * Returning continueExecution will allow lower-priority handlers to execute.
 *
 * By default, the main asio execution loop will register a low priority
 * (prioOpenBmcBase) handler for SIGINT and SIGTERM to cause the process to stop
 * on either of those signals. To prevent one of those signals from causing the
 * process to stop, simply register a higher priority handler that returns
 * breakExecution.
 *
 * @param int - priority of handler
 * @param int - signal number to wait for
 * @param handler - the callback function to be executed
 */
void registerSignalHandler(int priority, int signalNumber,
                           const std::function<SignalResponse(int)>& handler);

namespace session
{

// Session Related macros
constexpr auto sessionManagerRoot = "/xyz/openbmc_project/Ipmi/SessionInfo";
constexpr auto sessionIntf = "xyz.openbmc_project.Ipmi.SessionInfo";
constexpr auto sessionService = "xyz.openbmc_project.netipmid";
constexpr uint8_t searchCurrentSession = 0x00;
constexpr uint8_t searchSessionByHandle = 0xFE;
constexpr uint8_t searchSessionByID = 0xFF;
constexpr uint8_t ipmi20VerSession = 0x80;
constexpr size_t maxSessionCount = 15;
constexpr size_t sessionZero = 0;
constexpr size_t maxSessionlessCount = 1;
constexpr uint8_t invalidSessionID = 0;
constexpr uint8_t macAddrLen = 6;

enum class SessionState
{
    inActive,           // Session is not in use
    setupInProgress,    // Session Setup Sequence is progressing
    active,             // Session is active
    tearDownInProgress, // When Closing Session
};

} // namespace session
