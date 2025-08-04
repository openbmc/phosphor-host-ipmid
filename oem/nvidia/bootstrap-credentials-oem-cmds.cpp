/*
 * SPDX-FileCopyrightText: Copyright (c) 2024-2025 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "oemcommands.hpp"

#include <ipmid/api.hpp>
#include <ipmid/types.hpp>

#include <cstdint>

void registerBootstrapCredentialsOemCommands() __attribute__((constructor));

namespace ipmi
{
ipmi::RspType<uint8_t, uint8_t> ipmiGetUsbVendorIdProductId(uint8_t type)
{
    constexpr uint8_t descriptorVendorId = 1;
    constexpr uint8_t descriptorProductId = 2;

    // IPMI OEM USB Linux Gadget info
    constexpr uint16_t usbVendorId = 0x0525;
    constexpr uint16_t usbProductId = 0xA4A2;

    if (type == descriptorVendorId)
    {
        return ipmi::responseSuccess(static_cast<uint8_t>(usbVendorId >> 8),
                                     static_cast<uint8_t>(usbVendorId & 0xFF));
    }
    else if (type == descriptorProductId)
    {
        return ipmi::responseSuccess(static_cast<uint8_t>(usbProductId >> 8),
                                     static_cast<uint8_t>(usbProductId & 0xFF));
    }
    return ipmi::responseInvalidFieldRequest();
}

} // namespace ipmi

void registerBootstrapCredentialsOemCommands()
{
    ipmi::registerHandler(
        ipmi::prioOemBase, ipmi::groupNvidia,
        ipmi::bootstrap_credentials_oem::cmdGetUsbVendorIdProductId,
        ipmi::Privilege::Admin, ipmi::ipmiGetUsbVendorIdProductId);
}
