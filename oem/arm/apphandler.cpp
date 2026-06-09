/*
 * SPDX-FileCopyrightText: Copyright OpenBMC Authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <ipmid/api.hpp>

#include <cstdint>

void registerArmNetFnAppFunctions() __attribute__((constructor));

namespace
{
constexpr uint8_t ssifSystemInterfaceSelector = 0x00;
constexpr uint8_t reservedResponseByte = 0x00;
constexpr uint8_t ssifVersion = 0x00;
constexpr uint8_t ssifVersionMask = 0x07;
constexpr uint8_t supportsMultiPartReadsWrites = 0x80;
constexpr uint8_t supportsPec = 0x08;
constexpr uint8_t supportedInterfaceMask = 0x0F;
constexpr uint8_t reservedInterfaceBitsMask = 0xF0;

constexpr uint8_t ssifInputMessageSize = 0xFF;
+// IPMI v2.0 section 22.9 reports the SSIF output size as IPMI message bytes.
+// Making the output size as 0xFF - 3 to leave room for the response
+// NetFn/LUN, command, and completion code bytes in a 255-byte SSIF transfer.
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

    return ipmi::responseSuccess(reservedResponseByte, ssifCapabilities,
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
