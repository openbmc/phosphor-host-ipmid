/*
 * SPDX-FileCopyrightText: Copyright (c) 2024-2025 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "oemcommands.hpp"

#include <ipmid/api.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>

#include <cstdint>
#include <fstream>

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

ipmi::RspType<ipmi::message::Payload> ipmiGetUsbSerialNumber()
{
    static constexpr uint8_t usbSerialNumber = 0x00;
    ipmi::message::Payload usbSerialNumberPayload;
    usbSerialNumberPayload.pack(usbSerialNumber);
    return ipmi::responseSuccess(usbSerialNumberPayload);
}

ipmi::RspType<ipmi::message::Payload> ipmiGetRedfishHostName(
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
        lg2::error("ipmiGetRedfishHostName failed to get Network SystemConfig "
                   "object: {STATUS}",
                   "STATUS", ec.message());
        return ipmi::responseResponseError();
    }

    std::string hostName{};
    ec = ipmi::getDbusProperty<std::string>(
        ctx, service, networkConfigObj, networkConfigIface, "HostName",
        hostName);
    if (ec)
    {
        lg2::error("ipmiGetRedfishHostName failed to get HostName from Network "
                   "SystemConfig service: {STATUS}",
                   "STATUS", ec.message());
        return ipmi::responseResponseError();
    }
    ipmi::message::Payload hostNamePayload;
    hostNamePayload.pack(
        std::vector<uint8_t>(hostName.begin(), hostName.end()));
    return ipmi::responseSuccess(hostNamePayload);
}

ipmi::RspType<uint8_t> ipmiGetIpmiChannelRfHi()
{
    static constexpr const char* channelConfigDefaultFilename =
        "/usr/share/ipmi-providers/channel_config.json";
    std::ifstream channelConfigFile(channelConfigDefaultFilename);
    if (!channelConfigFile.is_open())
    {
        lg2::error("ipmiGetipmiChannelRfHi failed to open channel config file: "
                   "{STATUS}",
                   "STATUS", channelConfigDefaultFilename);
        return ipmi::responseResponseError();
    }

    nlohmann::json data = nullptr;
    try
    {
        data = nlohmann::json::parse(channelConfigFile, nullptr, false);
    }
    catch (const nlohmann::json::parse_error& e)
    {
        lg2::error(
            "ipmiGetipmiChannelRfHi failed to parse channel config file: "
            "{STATUS}",
            "STATUS", e.what());
        channelConfigFile.close();
        return ipmi::responseResponseError();
    }

    channelConfigFile.close();
    constexpr auto mediumType = "medium_type";
    constexpr auto protocolType = "protocol_type";
    constexpr auto sessionSupported = "session_supported";
    constexpr auto isIpmi = "is_ipmi";
    constexpr auto name = "name";
    constexpr auto channelInfo = "channel_info";
    constexpr auto isValid = "is_valid";
    constexpr auto redfishHostInterfaceChannel = "usb0";

    for (const auto& [key, value] : data.items())
    {
        if (value.is_null() || !value.contains(name) ||
            !value.contains(channelInfo) || !value.contains(isValid))
        {
            continue;
        }

        const std::string& channelName = value[name];
        if (channelName.find(redfishHostInterfaceChannel) == std::string::npos)
        {
            continue;
        }

        if (!value[isValid].get<bool>())
        {
            continue;
        }

        const auto& info = value[channelInfo];
        if (!info.contains(mediumType) || !info.contains(protocolType) ||
            !info.contains(sessionSupported) || !info.contains(isIpmi))
        {
            continue;
        }

        if (info[mediumType] == "lan-802.3" &&
            info[protocolType] == "ipmb-1.0" &&
            info[sessionSupported] == "multi-session" &&
            info[isIpmi].get<bool>())
        {
            uint8_t channelNum = static_cast<uint8_t>(std::stoi(key));
            return ipmi::responseSuccess(channelNum);
        }
    }
    lg2::error("ipmiGetipmiChannelRfHi no valid Redfish-compatible channel "
               "found");
    return ipmi::responseInvalidCommandOnLun();
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

    ipmi::registerHandler(
        ipmi::prioOemBase, ipmi::groupNvidia,
        ipmi::bootstrap_credentials_oem::cmdGetIpmiChannelRfHi,
        ipmi::Privilege::Admin, ipmi::ipmiGetIpmiChannelRfHi);
}
