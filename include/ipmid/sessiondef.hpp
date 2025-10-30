// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2019 Intel Corporation

#pragma once

#include <stddef.h>
#include <stdint.h>

namespace session
{

static constexpr auto sessionManagerRootPath =
    "/xyz/openbmc_project/ipmi/session";
static constexpr auto sessionIntf = "xyz.openbmc_project.Ipmi.SessionInfo";
static constexpr uint8_t ipmi20VerSession = 0x01;
static constexpr size_t maxSessionCountPerChannel = 15;
static constexpr size_t sessionZero = 0;
static constexpr size_t maxSessionlessCount = 1;
static constexpr uint8_t invalidSessionID = 0;
static constexpr uint8_t invalidSessionHandle = 0;
static constexpr uint8_t defaultSessionHandle = 0xFF;
static constexpr uint8_t maxNetworkInstanceSupported = 4;
static constexpr uint8_t ccInvalidSessionId = 0x87;
static constexpr uint8_t ccInvalidSessionHandle = 0x88;
static constexpr uint8_t searchCurrentSession = 0;
static constexpr uint8_t searchSessionByHandle = 0xFE;
static constexpr uint8_t searchSessionById = 0xFF;
// MSB BIT 7 BIT 6 assigned for netipmid instance in session handle.
static constexpr uint8_t multiIntfaceSessionHandleMask = 0x3F;

// MSB BIT 31-BIT30 assigned for netipmid instance in session ID
static constexpr uint32_t multiIntfaceSessionIDMask = 0x3FFFFFFF;

enum class State : uint8_t
{
    inactive,           // Session is not in use
    setupInProgress,    // Session Setup Sequence is progressing
    active,             // Session is active
    tearDownInProgress, // When Closing Session
};

} // namespace session
