/*
 * SPDX-FileCopyrightText: Copyright (c) 2024-2025 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "config.h"

#include "oemcommands.hpp"

#include <ipmid/api.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/lg2.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

void registerSbmrOemCommands() __attribute__((constructor));

constexpr auto loggingService = "xyz.openbmc_project.Logging";
constexpr auto loggingObject = "/xyz/openbmc_project/logging";
constexpr auto loggingInterface = "xyz.openbmc_project.Logging.Create";

namespace ipmi
{

ipmi::RspType<uint8_t> ipmiOemSbmrSendDescription(
    ipmi::Context::ptr ctx, uint8_t statusCode, uint8_t, uint8_t,
    uint8_t severity, uint8_t operation1st, uint8_t operation2nd,
    uint8_t subClass, uint8_t codeClass, std::vector<uint8_t> description)
{
    constexpr size_t maxDescriptionLength = 256;
    constexpr uint8_t bootProgressCode = 0x01;
    constexpr uint8_t bootErrorCode = 0x02;
    constexpr uint8_t bootDebugCode = 0x03;

    // Severity codes
    constexpr uint8_t minor = 0x40;
    constexpr uint8_t major = 0x80;
    constexpr uint8_t unrecovered = 0x90;
    constexpr uint8_t uncontained = 0xA0;

    if (description.size() > maxDescriptionLength)
    {
        return responseReqDataLenExceeded();
    }
    if (!description.empty() && description.back() != '\0')
    {
        return responseInvalidFieldRequest();
    }

    std::string messageData;
    for (uint8_t byte : description)
    {
        if (byte > 0x00 && byte < 0x1F)
        {
            return responseInvalidFieldRequest();
        }
        messageData.push_back(byte);
    }
    ipmi::ChannelInfo chInfo;
    auto cc = ipmi::getChannelInfo(ctx->channel, chInfo);
    if (cc != ipmi::ccSuccess)
    {
        lg2::error("Failed to get Channel Info: {STATUS}", "STATUS", cc);
        return ipmi::responseUnspecifiedError();
    }
    if ((chInfo.mediumType !=
         static_cast<uint8_t>(ipmi::EChannelMediumType::smbusV20)) &&
        (chInfo.mediumType !=
         static_cast<uint8_t>(ipmi::EChannelMediumType::systemInterface)) &&
        (chInfo.mediumType !=
         static_cast<uint8_t>(ipmi::EChannelMediumType::oem)))

    {
        lg2::error("ipmiOemSbmrSendDescription: Error - supported only in SSIF "
                   "interface");
        return ipmi::responseCommandNotAvailable();
    }
    std::ostringstream hexCode;
    hexCode << "0x" << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<int>(codeClass) << std::setw(2)
            << static_cast<int>(subClass) << std::setw(2)
            << static_cast<int>(operation2nd) << std::setw(2)
            << static_cast<int>(operation1st);

    std::string eventMessage;
    std::string eventSeverity;
    constexpr std::array<std::pair<uint8_t, std::string_view>, 4> sevMap{
        {{minor, "Minor"},
         {major, "Major"},
         {unrecovered, "Unrecovered"},
         {uncontained, "Uncontained"}}};
    switch (statusCode)
    {
        case bootProgressCode:
            eventMessage = "Progress Code ";
            eventSeverity =
                "xyz.openbmc_project.Logging.Entry.Level.Informational";
            break;
        case bootErrorCode:
            eventMessage = "Error Code ";
            if (auto it = std::ranges::find_if(
                    sevMap,
                    [severity](auto&& p) { return p.first == severity; });
                it != sevMap.end())
            {
                eventMessage += it->second;
            }
            eventSeverity =
                (severity == minor)
                    ? "xyz.openbmc_project.Logging.Entry.Level.Warning"
                    : "xyz.openbmc_project.Logging.Entry.Level.Error";
            break;
        case bootDebugCode:
            eventMessage = "Debug Code ";
            eventSeverity = "xyz.openbmc_project.Logging.Entry.Level.Debug";
            break;
        default:
            lg2::error("ipmiOemSbmrSendDescription: Invalid Status Code {CODE}",
                       "CODE", statusCode);
            return responseInvalidFieldRequest();
    }
    eventMessage += hexCode.str();
    eventMessage += ":" + messageData;
    std::map<std::string, std::string> additionalData;
    boost::system::error_code ec = ipmi::callDbusMethod(
        ctx, loggingService, loggingObject, loggingInterface, "Create",
        eventMessage, eventSeverity, additionalData);
    if (ec.value())
    {
        lg2::error("Failed to call Create method, Error={ERROR}", "ERROR",
                   ec.message());
        return ipmi::responseUnspecifiedError();
    }
    return ipmi::responseSuccess();
}
} // namespace ipmi

void registerSbmrOemCommands()
{
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::groupNvidia,
                          ipmi::sbmr_oem::cmdSbmrSendDescription,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiOemSbmrSendDescription);
}
