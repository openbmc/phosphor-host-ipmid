/*
 * SPDX-FileCopyrightText: Copyright (c) 2024-2025 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "oemcommands.hpp"

#include <ipmid/api.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/lg2.hpp>

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

ipmi::RspType<std::vector<uint8_t>> ipmiGetUsbSerialNumber()
{
    static constexpr uint8_t usbSerialNumber = 0x00;
    std::vector<uint8_t> usbSerialNumberVector = {usbSerialNumber};
    return ipmi::responseSuccess(usbSerialNumberVector);
}

ipmi::RspType<std::vector<uint8_t>> ipmiGetRedfishHostName(
    ipmi::Context::ptr ctx)
{
    std::string service{};
    constexpr auto networkConfigObj = "/xyz/openbmc_project/network/config";
    constexpr auto networkConfigIface =
        "xyz.openbmc_project.Network.SystemConfiguration";
    boost::system::error_code ec =
        ipmi::getService(ctx, networkConfigIface, networkConfigObj, service);
    if (ec)
    {
        lg2::error(
            "ipmiGetRedfishHostName failed to get Network SystemConfiguration object {STATUS}",
            "STATUS", ec.what());
        return ipmi::responseResponseError();
    }

    std::string hostName{};
    ec = ipmi::getDbusProperty<std::string>(
        ctx, service, networkConfigObj, networkConfigIface, "HostName",
        hostName);
    if (ec)
    {
        lg2::error(
            "ipmiGetRedfishHostName failed to get HostName from Network SystemConfiguration service {STATUS}",
            "STATUS", ec.what());
        return ipmi::responseResponseError();
    }
    std::vector<uint8_t> hostNameBuffer;
    std::copy(hostName.begin(), hostName.end(),
              std::back_inserter(hostNameBuffer));
    return ipmi::responseSuccess(hostNameBuffer);
}
} // namespace ipmi

void registerBootstrapCredentialsOemCommands()
{
    ipmi::registerHandler(
        ipmi::prioOemBase, ipmi::groupNvidia,
        ipmi::bootstrap_credentials_oem::cmdGetUsbVendorIdProductId,
        ipmi::Privilege::Admin, ipmi::ipmiGetUsbVendorIdProductId);

    ipmi::registerHandler(
        ipmi::prioOemBase, ipmi::groupNvidia,
        ipmi::bootstrap_credentials_oem::cmdGetUsbSerialNumber,
        ipmi::Privilege::Admin, ipmi::ipmiGetUsbSerialNumber);

    ipmi::registerHandler(
        ipmi::prioOemBase, ipmi::groupNvidia,
        ipmi::bootstrap_credentials_oem::cmdGetRedfishHostName,
        ipmi::Privilege::Admin, ipmi::ipmiGetRedfishHostName);
}
