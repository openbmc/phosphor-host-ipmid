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
#include <unordered_map>

void registerBootstrapCredentialsOemCommands() __attribute__((constructor));

// IPMI OEM USB Linux Gadget info
static constexpr uint16_t usbVendorId = 0x0525;
static constexpr uint16_t usbProductId = 0xA4A2;

namespace ipmi
{
ipmi::RspType<uint8_t, uint8_t> ipmiGetUsbDescription(uint8_t type)
{
    static const std::unordered_map<uint8_t, uint16_t> usbInfo = {
        {0x01, usbVendorId},
        {0x02, usbProductId},
    };
    if (auto it = usbInfo.find(type); it != usbInfo.end())
    {
        const auto id = it->second;
        return ipmi::responseSuccess(static_cast<uint8_t>(id >> 8),
                                     static_cast<uint8_t>(id));
    }
    return ipmi::responseInvalidFieldRequest();
}

} // namespace ipmi

void registerBootstrapCredentialsOemCommands()
{
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::groupNvidia,
                          ipmi::bootstrap_credentials_oem::cmdGetUsbDescription,
                          ipmi::Privilege::Admin, ipmi::ipmiGetUsbDescription);
}
