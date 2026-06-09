/*
 * SPDX-FileCopyrightText: Copyright OpenBMC Authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "config.h"

#include <ipmid/api.hpp>

#include <cstdint>

void registerArmNetFnAppFunctions() __attribute__((constructor));

namespace
{
constexpr uint8_t ssifSystemInterfaceSelector = 0x00;
constexpr uint8_t ssifVersion = 0x00;
constexpr uint8_t ssifVersionMask = 0x07;
constexpr uint8_t supportsMultiPartReadsWrites = 0x80;
constexpr uint8_t supportsPec = 0x08;
constexpr uint8_t supportedInterfaceMask = 0x0F;
constexpr uint8_t reservedInterfaceBitsMask = 0xF0;

constexpr uint8_t ssifInputMessageSize = 0xFF;
constexpr uint8_t ssifOutputMessageSize = 0xFF - 3;
constexpr uint8_t ssifCapabilities =
    supportsMultiPartReadsWrites | supportsPec |
    (ssifVersion & ssifVersionMask);
} // namespace

ipmi::RspType<uint8_t, uint8_t, uint8_t, uint8_t>
    ipmiAppGetSystemInterfaceCapabilities(uint8_t interfaceSelector)
{
    if ((interfaceSelector & reservedInterfaceBitsMask) != 0)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    if ((interfaceSelector & supportedInterfaceMask) !=
        ssifSystemInterfaceSelector)
    {
        return ipmi::responseParmOutOfRange();
    }

    return ipmi::responseSuccess(0x00, ssifCapabilities,
                                 ssifInputMessageSize,
                                 ssifOutputMessageSize);
}

void registerArmNetFnAppFunctions()
{
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnApp,
                          ipmi::app::cmdGetSystemIfCapabilities,
                          ipmi::Privilege::User,
                          ipmiAppGetSystemInterfaceCapabilities);
}
