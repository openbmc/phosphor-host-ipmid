#include "session_cmds.hpp"

#include "endian.hpp"
#include "sessions_manager.hpp"

#include <ipmid/api.h>

#include <ipmid/sessionhelper.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/lg2.hpp>

#include <chrono>

using namespace std::chrono_literals;

namespace command
{

std::vector<uint8_t>
    setSessionPrivilegeLevel(const std::vector<uint8_t>& inPayload,
                             std::shared_ptr<message::Handler>& handler)
{
    auto request =
        reinterpret_cast<const SetSessionPrivLevelReq*>(inPayload.data());
    if (inPayload.size() != sizeof(*request))
    {
        std::vector<uint8_t> errorPayload{IPMI_CC_REQ_DATA_LEN_INVALID};
        return errorPayload;
    }
    if (request->reserved != 0)
    {
        std::vector<uint8_t> errorPayload{IPMI_CC_INVALID_FIELD_REQUEST};
        return errorPayload;
    }

    std::vector<uint8_t> outPayload(sizeof(SetSessionPrivLevelResp));
    auto response =
        reinterpret_cast<SetSessionPrivLevelResp*>(outPayload.data());
    response->completionCode = IPMI_CC_OK;
    uint8_t reqPrivilegeLevel = request->reqPrivLevel;

    auto session = session::Manager::get().getSession(handler->sessionID);

    if (reqPrivilegeLevel == 0) // Just return present privilege level
    {
        response->newPrivLevel = session->currentPrivilege();
        return outPayload;
    }
    if (reqPrivilegeLevel ==
            static_cast<uint8_t>(session::Privilege::CALLBACK) ||
        reqPrivilegeLevel > static_cast<uint8_t>(session::Privilege::OEM))
    {
        response->completionCode = IPMI_CC_INVALID_FIELD_REQUEST;
        return outPayload;
    }

    if (reqPrivilegeLevel > (static_cast<uint8_t>(session->reqMaxPrivLevel) &
                             session::reqMaxPrivMask))
    {
        // Requested level exceeds Channel and/or User Privilege Limit
        response->completionCode = IPMI_CC_EXCEEDS_USER_PRIV;
        return outPayload;
    }
    // Use the minimum privilege of user or channel
    uint8_t minPriv = 0;
    if (session->sessionChannelAccess.privLimit <
        session->sessionUserPrivAccess.privilege)
    {
        minPriv = session->sessionChannelAccess.privLimit;
    }
    else
    {
        minPriv = session->sessionUserPrivAccess.privilege;
    }
    if (reqPrivilegeLevel > minPriv)
    {
        // Requested level exceeds Channel and/or User Privilege Limit
        response->completionCode = IPMI_CC_EXCEEDS_USER_PRIV;
    }
    else
    {
        // update current privilege of the session.
        session->currentPrivilege(static_cast<uint8_t>(reqPrivilegeLevel));
        response->newPrivLevel = reqPrivilegeLevel;
    }

    return outPayload;
}

/**
 * @brief set the session state as teardown
 *
 * This function is to set the session state to tear down in progress if the
 * state is active.
 *
 * @param[in] busp - Dbus obj
 * @param[in] service - service name
 * @param[in] obj - object path
 *
 * @return success completion code if it sets the session state to
 * tearDownInProgress else return the corresponding error completion code.
 **/
uint8_t setSessionState(std::shared_ptr<sdbusplus::asio::connection>& busp,
                        const std::string& service, const std::string& obj)
{
    try
    {
        uint8_t sessionState = std::get<uint8_t>(ipmi::getDbusProperty(
            *busp, service, obj, session::sessionIntf, "State"));

        if (sessionState == static_cast<uint8_t>(session::State::active))
        {
            ipmi::setDbusProperty(
                *busp, service, obj, session::sessionIntf, "State",
                static_cast<uint8_t>(session::State::tearDownInProgress));
            return ipmi::ccSuccess;
        }
    }
    catch (const std::exception& e)
    {
        lg2::error(
            "Failed in getting session state property: {SERVICE}, {PATH}, {INTERFACE}",
            "SERVICE", service, "PATH", obj, "INTERFACE", session::sessionIntf);
        return ipmi::ccUnspecifiedError;
    }

    return ipmi::ccInvalidFieldRequest;
}

uint8_t closeOtherNetInstanceSession(const uint32_t reqSessionId,
                                     const uint8_t reqSessionHandle,
                                     const uint8_t currentSessionPriv)
{
    auto busp = getSdBus();

    try
    {
        ipmi::ObjectTree objectTree = ipmi::getAllDbusObjects(
            *busp, session::sessionManagerRootPath, session::sessionIntf);

        for (auto& objectTreeItr : objectTree)
        {
            const std::string obj = objectTreeItr.first;

            if (isSessionObjectMatched(obj, reqSessionId, reqSessionHandle))
            {
                auto& serviceMap = objectTreeItr.second;

                if (serviceMap.size() != 1)
                {
                    return ipmi::ccUnspecifiedError;
                }

                auto itr = serviceMap.begin();
                const std::string service = itr->first;
                uint8_t closeSessionPriv =
                    std::get<uint8_t>(ipmi::getDbusProperty(
                        *busp, service, obj, session::sessionIntf,
                        "CurrentPrivilege"));

                if (currentSessionPriv < closeSessionPriv)
                {
                    return ipmi::ccInsufficientPrivilege;
                }
                return setSessionState(busp, service, obj);
            }
        }
    }
    catch (const sdbusplus::exception_t& e)
    {
        lg2::error(
            "Failed to fetch object from dbus, interface: {INTERFACE}, error: {ERROR}",
            "INTERFACE", session::sessionIntf, "ERROR", e);
        return ipmi::ccUnspecifiedError;
    }

    return ipmi::ccInvalidFieldRequest;
}

uint8_t closeMyNetInstanceSession(uint32_t reqSessionId,
                                  uint8_t reqSessionHandle,
                                  const uint8_t currentSessionPriv)
{
    bool status = false;

    try
    {
        if (reqSessionId == session::sessionZero)
        {
            reqSessionId = session::Manager::get().getSessionIDbyHandle(
                reqSessionHandle & session::multiIntfaceSessionHandleMask);
            if (!reqSessionId)
            {
                return session::ccInvalidSessionHandle;
            }
        }
    }
    catch (const std::exception& e)
    {
        lg2::error(
            "Failed to get session manager instance or sessionID by sessionHandle: {ERROR}",
            "ERROR", e);
        return session::ccInvalidSessionHandle;
    }

    try
    {
        auto closeSessionInstance =
            session::Manager::get().getSession(reqSessionId);
        uint8_t closeSessionPriv = closeSessionInstance->currentPrivilege();

        if (currentSessionPriv < closeSessionPriv)
        {
            return ipmi::ccInsufficientPrivilege;
        }
    }
    catch (const std::exception& e)
    {
        lg2::error(
            "Failed to get session manager instance or sessionID: {ERROR}",
            "ERROR", e);
        return session::ccInvalidSessionId;
    }

    try
    {
        status = session::Manager::get().stopSession(reqSessionId);

        if (!status)
        {
            return session::ccInvalidSessionId;
        }
    }
    catch (const std::exception& e)
    {
        lg2::error(
            "Failed to get session manager instance or stop session: {ERROR}",
            "ERROR", e);
        return ipmi::ccUnspecifiedError;
    }

    return ipmi::ccSuccess;
}

std::vector<uint8_t> closeSession(const std::vector<uint8_t>& inPayload,
                                  std::shared_ptr<message::Handler>& handler)
{
    // minimum inPayload size is reqSessionId (uint32_t)
    // maximum inPayload size is struct CloseSessionRequest
    if (inPayload.size() != sizeof(uint32_t) &&
        inPayload.size() != sizeof(CloseSessionRequest))
    {
        std::vector<uint8_t> errorPayload{IPMI_CC_REQ_DATA_LEN_INVALID};
        return errorPayload;
    }

    auto request =
        reinterpret_cast<const CloseSessionRequest*>(inPayload.data());

    std::vector<uint8_t> outPayload(sizeof(CloseSessionResponse));
    auto response = reinterpret_cast<CloseSessionResponse*>(outPayload.data());
    uint32_t reqSessionId = request->sessionID;
    uint8_t ipmiNetworkInstance = 0;
    uint8_t currentSessionPriv = 0;
    uint8_t reqSessionHandle = session::invalidSessionHandle;

    if (inPayload.size() == sizeof(CloseSessionRequest))
    {
        reqSessionHandle = request->sessionHandle;
    }

    if (reqSessionId == session::sessionZero &&
        reqSessionHandle == session::invalidSessionHandle)
    {
        response->completionCode = session::ccInvalidSessionHandle;
        return outPayload;
    }

    if (inPayload.size() == sizeof(reqSessionId) &&
        reqSessionId == session::sessionZero)
    {
        response->completionCode = session::ccInvalidSessionId;
        return outPayload;
    }

    if (reqSessionId != session::sessionZero &&
        inPayload.size() != sizeof(reqSessionId))
    {
        response->completionCode = ipmi::ccInvalidFieldRequest;
        return outPayload;
    }

    try
    {
        ipmiNetworkInstance = session::Manager::get().getNetworkInstance();
        auto currentSession =
            session::Manager::get().getSession(handler->sessionID);
        currentSessionPriv = currentSession->currentPrivilege();
    }
    catch (const sdbusplus::exception_t& e)
    {
        lg2::error(
            "Failed to fetch object from dbus, interface: {INTERFACE}, error: {ERROR}",
            "INTERFACE", session::sessionIntf, "ERROR", e);
        response->completionCode = ipmi::ccUnspecifiedError;
        return outPayload;
    }

    if (reqSessionId >> myNetInstanceSessionIdShiftMask ==
            ipmiNetworkInstance ||
        (reqSessionId == session::sessionZero &&
         (reqSessionHandle >> myNetInstanceSessionHandleShiftMask ==
          ipmiNetworkInstance)))
    {
        response->completionCode = closeMyNetInstanceSession(
            reqSessionId, reqSessionHandle, currentSessionPriv);
        session::Manager::get().scheduleSessionCleaner(100us);
    }
    else
    {
        response->completionCode = closeOtherNetInstanceSession(
            reqSessionId, reqSessionHandle, currentSessionPriv);
    }

    return outPayload;
}

} // namespace command
