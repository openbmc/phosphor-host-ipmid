/*
 * SPDX-FileCopyrightText: Copyright (c) 2024-2025 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "config.h"

#include "oemcommands.hpp"

#include <ipmid/api.hpp>
#include <ipmid/types.hpp>

#include <cstdint>

void registerBootstrapCredentialsOemCommands() __attribute__((constructor));

// IPMI OEM USB Linux Gadget info
static constexpr uint16_t usbVendorId = 0x0525;
static constexpr uint16_t usbProductId = 0xA4A2;

namespace ipmi
{
ipmi::RspType<uint8_t, uint8_t> ipmiGetUsbDescription(uint8_t type)
{
    constexpr uint8_t descriptorVendorId = 1;
    constexpr uint8_t descriptorProductId = 2;
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

ipmi::RspType<> ipmiGetUsbSerialNumber()
{
    static constexpr uint8_t usbSerialNumber = 0x00;
    std::vector<uint8_t> usbSerialNumberVector = {usbSerialNumber};
    return ipmi::responseSuccess(usbSerialNumberVector);
}

} // namespace ipmi

void registerBootstrapCredentialsOemCommands()
{
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::groupNvidia,
                          ipmi::bootstrap_credentials_oem::cmdGetUsbDescription,
                          ipmi::Privilege::Admin, ipmi::ipmiGetUsbDescription);

    ipmi::registerHandler(
        ipmi::prioOemBase, ipmi::groupNvidia,
        ipmi::bootstrap_credentials_oem::cmdGetUsbSerialNumber,
        ipmi::Privilege::Admin, ipmi::ipmiGetUsbSerialNumber);
}
