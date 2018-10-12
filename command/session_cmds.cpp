#include "session_cmds.hpp"

#include "endian.hpp"
#include "main.hpp"

#include <host-ipmid/ipmid-api.h>

#include <iostream>

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

    auto session = (std::get<session::Manager&>(singletonPool)
                        .getSession(handler.sessionID))
                       .lock();

    if (reqPrivilegeLevel == 0) // Just return present privilege level
    {
        response->newPrivLevel = static_cast<uint8_t>(session->curPrivLevel);
    }
    else if (reqPrivilegeLevel <= static_cast<uint8_t>(session->maxPrivLevel))
    {
        session->curPrivLevel =
            static_cast<session::Privilege>(reqPrivilegeLevel);
        response->newPrivLevel = reqPrivilegeLevel;
    }
    else
    {
        // Requested level exceeds Channel and/or User Privilege Limit
        response->completionCode = IPMI_CC_EXCEEDS_USER_PRIV;
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
