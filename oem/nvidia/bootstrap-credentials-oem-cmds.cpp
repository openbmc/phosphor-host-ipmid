/*
 * SPDX-FileCopyrightText: Copyright OpenBMC Authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "oemcommands.hpp"

#include <ipmid/api.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>

#include <array>
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
    constexpr auto redfishHostInterfaceChannel = "usb0";
    uint8_t chNum = ipmi::getChannelByName(redfishHostInterfaceChannel);
    ChannelInfo chInfo{};
    Cc compCode = ipmi::getChannelInfo(chNum, chInfo);
    if (compCode != ipmi::ccSuccess)
    {
        lg2::error(
            "ipmiGetIpmiChannelRfHi failed for channel {CHANNEL} with error {ERROR}",
            "CHANNEL", chNum, "ERROR", compCode);
        return ipmi::responseUnspecifiedError();
    }

    if (chInfo.mediumType !=
            static_cast<uint8_t>(EChannelMediumType::lan8032) ||
        chInfo.protocolType !=
            static_cast<uint8_t>(EChannelProtocolType::ipmbV10) ||
        chInfo.sessionSupported !=
            static_cast<uint8_t>(EChannelSessSupported::multi) ||
        chInfo.isIpmi != true)
    {
        lg2::error(
            "ipmiGetIpmiChannelRfHi: channel {CHANNEL} lacks required config",
            "CHANNEL", chNum);
        return responseSensorInvalid();
    }
    return ipmi::responseSuccess(static_cast<uint8_t>(chNum));
}

bool getRfUuid(std::string& rfUuid)
{
    constexpr const char* bmcwebPersistentDataFile =
        "/home/root/bmcweb_persistent_data.json";
    std::ifstream f(bmcwebPersistentDataFile);
    if (!f.is_open())
    {
        lg2::error("Failed to open {FILE}", "FILE", bmcwebPersistentDataFile);
        return false;
    }
    auto data = nlohmann::json::parse(f, nullptr, false);
    if (data.is_discarded())
    {
        lg2::error("Failed to parse {FILE}", "FILE", bmcwebPersistentDataFile);
        return false;
    }

    if (auto it = data.find("system_uuid"); it != data.end() && it->is_string())
    {
        rfUuid = *it;
        return true;
    }

    lg2::error("system_uuid missing in {FILE}", "FILE",
               bmcwebPersistentDataFile);
    return false;
}

ipmi::RspType<std::vector<uint8_t>> ipmiGetRedfishServiceUUID()
{
    std::string rfUuid;
    bool ret = getRfUuid(rfUuid);
    if (!ret)
    {
        lg2::error(
            "ipmiGetRedfishServiceUUID: Error reading Redfish Service UUID File.");
        return ipmi::responseResponseError();
    }

    // As per Redfish Host Interface Spec v1.3.0
    // The Redfish UUID is 16byte and should be represented as below:
    // Ex: {00112233-4455-6677-8899-AABBCCDDEEFF}
    // 0x33 0x22 0x11 0x00 0x55 0x44 0x77 0x66 0x88 0x99 0xAA 0xBB 0xCC 0xDD
    // 0xEE 0xFF

    std::vector<uint8_t> resBuf;
    std::vector<std::string> groups = ipmi::split(rfUuid, '-');

    for (size_t i = 0; i < groups.size(); ++i)
    {
        auto group = groups[i];
        if (i < 3)
        {
            std::reverse(group.begin(), group.end());
        }

        for (size_t j = 0; j < group.size(); j += 2)
        {
            if (i < 3)
            {
                std::swap(group[j], group[j + 1]);
            }
            resBuf.push_back(static_cast<uint8_t>(
                std::stoi(group.substr(j, 2), nullptr, 16)));
        }
    }
    return ipmi::responseSuccess(resBuf);
}

ipmi::RspType<uint16_t> ipmiGetRedfishServicePort()
{
    constexpr uint16_t redfishPort = 443;
    return ipmi::responseSuccess(htons(redfishPort));
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

    ipmi::registerHandler(
        ipmi::prioOemBase, ipmi::groupNvidia,
        ipmi::bootstrap_credentials_oem::cmdGetRedfishServiceUUID,
        ipmi::Privilege::Admin, ipmi::ipmiGetRedfishServiceUUID);

    ipmi::registerHandler(
        ipmi::prioOemBase, ipmi::groupNvidia,
        ipmi::bootstrap_credentials_oem::cmdGetRedfishServicePort,
        ipmi::Privilege::Admin, ipmi::ipmiGetRedfishServicePort);
}
