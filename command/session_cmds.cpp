#include "session_cmds.hpp"

#include "endian.hpp"
#include "main.hpp"

#include <host-ipmid/ipmid-api.h>

#include <user_channel/channel_layer.hpp>
#include <user_channel/user_layer.hpp>

namespace command
{

std::vector<uint8_t>
    setSessionPrivilegeLevel(const std::vector<uint8_t>& inPayload,
                             const message::Handler& handler)
{

    std::vector<uint8_t> outPayload(sizeof(SetSessionPrivLevelResp));
    auto request =
        reinterpret_cast<const SetSessionPrivLevelReq*>(inPayload.data());
    auto response =
        reinterpret_cast<SetSessionPrivLevelResp*>(outPayload.data());
    response->completionCode = IPMI_CC_OK;
    uint8_t reqPrivilegeLevel = request->reqPrivLevel;

    auto session = std::get<session::Manager&>(singletonPool)
                       .getSession(handler.sessionID);

    if (reqPrivilegeLevel == 0) // Just return present privilege level
    {
        response->newPrivLevel = static_cast<uint8_t>(session->curPrivLevel);
        return outPayload;
    }
    if (reqPrivilegeLevel >
        (session->reqMaxPrivLevel & session::reqMaxPrivMask))
    {
        // Requested level exceeds Channel and/or User Privilege Limit
        response->completionCode = IPMI_CC_EXCEEDS_USER_PRIV;
        return outPayload;
    }

    uint8_t userId = ipmi::ipmiUserGetUserId(session->userName);
    if (userId == ipmi::invalidUserId)
    {
        response->completionCode = IPMI_CC_UNSPECIFIED_ERROR;
        return outPayload;
    }
    ipmi::PrivAccess userAccess{};
    ipmi::ChannelAccess chAccess{};
    if ((ipmi::ipmiUserGetPrivilegeAccess(userId, session->chNum, userAccess) !=
         IPMI_CC_OK) ||
        (ipmi::getChannelAccessData(session->chNum, chAccess) != IPMI_CC_OK))
    {
        response->completionCode = IPMI_CC_INVALID_PRIV_LEVEL;
        return outPayload;
    }
    // Use the minimum privilege of user or channel
    uint8_t minPriv = 0;
    if (chAccess.privLimit < userAccess.privilege)
    {
        minPriv = chAccess.privLimit;
    }
    else
    {
        minPriv = userAccess.privilege;
    }
    if (reqPrivilegeLevel > minPriv)
    {
        // Requested level exceeds Channel and/or User Privilege Limit
        response->completionCode = IPMI_CC_EXCEEDS_USER_PRIV;
    }
    else
    {
        // update current privilege of the session.
        session->curPrivLevel =
            static_cast<session::Privilege>(reqPrivilegeLevel);
        response->newPrivLevel = reqPrivilegeLevel;
    }

    return outPayload;
}

std::vector<uint8_t> closeSession(const std::vector<uint8_t>& inPayload,
                                  const message::Handler& handler)
{
    std::vector<uint8_t> outPayload(sizeof(CloseSessionResponse));
    auto request =
        reinterpret_cast<const CloseSessionRequest*>(inPayload.data());
    auto response = reinterpret_cast<CloseSessionResponse*>(outPayload.data());
    response->completionCode = IPMI_CC_OK;

    auto bmcSessionID = endian::from_ipmi(request->sessionID);

    // Session 0 is needed to handle session setup, so session zero is never
    // closed
    if (bmcSessionID == session::SESSION_ZERO)
    {
        response->completionCode = IPMI_CC_INVALID_SESSIONID;
    }
    else
    {
        auto status = std::get<session::Manager&>(singletonPool)
                          .stopSession(bmcSessionID);
        if (!status)
        {
            response->completionCode = IPMI_CC_INVALID_SESSIONID;
        }
    }
    return outPayload;
}

} // namespace command
