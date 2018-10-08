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

#include <host-ipmid/iana.hpp>
#include <ipmi/message/types.hpp>
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
enum Privilege
{
    privilegeNone = 0x00,
    privilegeCallback,
    privilegeUser,
    privilegeOperator,
    privilegeAdmin,
    privilegeOem,
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
// Note: these are also shifted left to make room for the LUN.
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
template <typename... Args>
static inline auto response(ipmi::Cc cc, Args&&... args)
{
    return std::make_tuple(cc, std::make_optional(std::make_tuple(args...)));
}
static inline auto response(ipmi::Cc cc)
{
    return std::make_tuple(cc, std::nullopt);
}
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

// TODO VM: how to make sure that this has ipmi::Cc as first arg?
template <typename... RetTypes>
using RspType = std::tuple<ipmi::Cc, std::optional<std::tuple<RetTypes...>>>;

} // namespace ipmi

// any client can interact with the main asio service
std::shared_ptr<boost::asio::io_service> getIoService();

// any client can interact with the main sdbus
std::shared_ptr<sdbusplus::asio::connection> getSdBus();

using work_t = void(void);
void post_work(work_t work);
