#include "channel_auth.hpp"

#include <host-ipmid/ipmid-api.h>

#include <iostream>

namespace command
{

std::vector<uint8_t>
    GetChannelCapabilities(const std::vector<uint8_t>& inPayload,
                           const message::Handler& handler)
{
    std::vector<uint8_t> outPayload(sizeof(GetChannelCapabilitiesResp));
    auto response =
        reinterpret_cast<GetChannelCapabilitiesResp*>(outPayload.data());

    // A canned response, since there is no user and channel management.
    response->completionCode = IPMI_CC_OK;

    // Channel Number 1 is arbitrarily applied to primary LAN channel;
    response->channelNumber = 1;

    response->ipmiVersion = 1; // IPMI v2.0 extended capabilities available.
    response->reserved1 = 0;
    response->oem = 0;
    response->straightKey = 0;
    response->reserved2 = 0;
    response->md5 = 0;
    response->md2 = 0;

    response->reserved3 = 0;
    response->KGStatus = 0;       // KG is set to default
    response->perMessageAuth = 0; // Per-message Authentication is enabled
    response->userAuth = 0;       // User Level Authentication is enabled
    response->nonNullUsers = 1;   // Non-null usernames enabled
    response->nullUsers = 1;      // Null usernames enabled
    response->anonymousLogin = 0; // Anonymous Login disabled

    response->reserved4 = 0;
    response->extCapabilities = 0x2; // Channel supports IPMI v2.0 connections

    response->oemID[0] = 0;
    response->oemID[1] = 0;
    response->oemID[2] = 0;
    response->oemAuxillary = 0;
    return outPayload;
}

} // namespace command
