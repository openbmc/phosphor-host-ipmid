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

#if __has_include(<optional>)
#include <optional>
#elif __has_include(<experimental/optional>)
#include <experimental/optional>
namespace std {
  // splice experimental::optional into std
  using std::experimental::optional;
  using std::experimental::make_optional;
  using std::experimental::nullopt;
}
#else
#  error optional not available
#endif

#include <ipmi/registration.hpp>

/* NOTE:
 *
 * This is intended for native C++ use. For the legacy C api, include
 * ipmid-api.h for a reduced functionality. Note that the C api is now marked
 * as deprecated and will be removed once all the internal users of it have
 * been updated to use the new C++ api.
 */

namespace ipmi
{

/*
 * Specifies the minimum privilege level required to execute the command
 * This means the command can be executed at a given privilege level or higher
 * privilege level. Those commands which can be executed via system interface
 * only should use SYSTEM_INTERFACE
 */
enum privilige {
  privilegeCallback = 0x01,
  privilegeUser,
  privilegeOperator,
  privilegeAdmin,
  privilegeOem,
};

// IPMI Net Function number as specified by IPMI V2.0 spec.
using netFn = uint8_t;

// IPMI Command for a Net Function number as specified by IPMI V2.0 spec.
using cmd = uint8_t;

// ipmi function return the status code
using cc = uint8_t;

// These are the command network functions, the response
// network functions are the function + 1. So to determine
// the proper network function which issued the command
// associated with a response, subtract 1.
// Note: these are also shifted left to make room for the LUN.
constexpr netFn netFnChassis   = 0x00;
constexpr netFn netFnBridge    = 0x02;
constexpr netFn netFnSensor    = 0x04;
constexpr netFn netFnApp       = 0x06;
constexpr netFn netFnFirmware  = 0x08;
constexpr netFn netFnStorage   = 0x0a;
constexpr netFn netFnTransport = 0x0c;

// IPMI commands for net functions. Callbacks using this should be careful to
// parse arguments to the sub-functions and can take advantage of the built-in
// message handling mechanism to create custom routing
constexpr cmd cmdWildcard = 0xFF;

// IPMI standard completion codes specified by the IPMI V2.0 spec.
//
// This might have been an enum class, but that would make it hard for
// OEM- and command-specific completion codes to be added elsewhere.
//
// Custom completion codes can be defined in individual modules for
// command specific errors in the 0x80-0xBE range
//
// Alternately, OEM completion codes are in the 0x01-0x7E range
constexpr cc ccSuccess                = 0x00;
constexpr cc ccBusy                   = 0xC0;
constexpr cc ccInvalidCommand         = 0xC1;
constexpr cc ccInvalidCommandOnLun    = 0xC2;
constexpr cc ccTimeout                = 0xC2;
constexpr cc ccOutOfSpace             = 0xC2;
constexpr cc ccInvalidReservationId   = 0xC5;
constexpr cc ccReqDataTruncated       = 0xC6;
constexpr cc ccReqDataLenInvalid      = 0xC7;
constexpr cc ccReqDataLenExceeded     = 0xC8;
constexpr cc ccParmOutOfRange         = 0xC9;
constexpr cc ccRetBytesUnavailable    = 0xCA;
constexpr cc ccSensorInvalid          = 0xCB;
constexpr cc ccInvalidFieldRequest    = 0xCC;
constexpr cc ccIllegalCommand         = 0xCD;
constexpr cc ccResponseError          = 0xCE;
constexpr cc ccDuplicateRequest       = 0xCF;
constexpr cc ccCmdFailSdrMode         = 0xD0;
constexpr cc ccCmdFailFwUpdMode       = 0xD1;
constexpr cc ccCmdFailInitAgent       = 0xD2;
constexpr cc ccDestinationUnavailable = 0xD3;
constexpr cc ccInsufficientPrivilege  = 0xD4;
constexpr cc ccCommandNotAvailable    = 0xD5;
constexpr cc ccCommandDisabled        = 0xD6;
constexpr cc ccUnspecifiedError       = 0xFF;


/* ipmi often has two return types:
 * 1. Failure: CC is non-zero; no trailing data
 * 2. Success: CC is zero; trailing data (usually a fixed type)
 *
 * using ipmi::response(cc, ...), it will automatically always pack
 * the correct type for the response without having to explicitly type out all
 * the parameters that the function would return.
 *
 * To enable this feature, you just define the ipmi function as returning an
 * ipmi::rspType which has the optional trailing data built in, with your types
 * defined as parameters.
 */
template<typename... Args>
auto response(ipmi::cc cc, Args&&... args)
{
  return std::make_tuple(cc, std::make_optional(std::make_tuple(args...)));
}
auto response(ipmi::cc cc)
{
  return std::make_tuple(cc, std::nullopt);
}

// TODO VM: how to make sure that this has ipmi::cc as first arg?
template <typename CC, typename... RetTypes>
using rspType = std::tuple<ipmi::cc, std::optional<std::tuple<RetTypes...>>>;

#if 0 /* no optional payload (TESTING only) */

template<typename... Args>
auto response(ipmi::cc cc, Args&&... args)
{
  return std::tuple_cat(std::make_tuple(cc), std::make_tuple(args...));
}
auto response(ipmi::cc cc)
{
  return std::make_tuple(cc);
}

// TODO VM: how to make sure that this has ipmi::cc as first arg?
template <typename CC, typename... RetTypes>
using rspType = std::tuple<ipmi::cc, RetTypes...>;

#endif /* optional response payload */

} // namespace ipmi
