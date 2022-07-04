#include "payload_cmds.hpp"

#include "sessions_manager.hpp"
#include "sol/sol_manager.hpp"
#include "sol_cmds.hpp"

#include <ipmid/api.h>

#include <ipmid/api-types.hpp>
#include <phosphor-logging/lg2.hpp>

namespace sol
{

namespace command
{

std::vector<uint8_t> activatePayload(const std::vector<uint8_t>& inPayload,
                                     std::shared_ptr<message::Handler>& handler)
{
    auto request =
        reinterpret_cast<const ActivatePayloadRequest*>(inPayload.data());
    if (inPayload.size() != sizeof(*request))
    {
        std::vector<uint8_t> errorPayload{IPMI_CC_REQ_DATA_LEN_INVALID};
        return errorPayload;
    }

    std::vector<uint8_t> outPayload(sizeof(ActivatePayloadResponse));
    auto response =
        reinterpret_cast<ActivatePayloadResponse*>(outPayload.data());

    response->completionCode = IPMI_CC_OK;

    // SOL is the payload currently supported for activation.
    if (static_cast<uint8_t>(message::PayloadType::SOL) != request->payloadType)
    {
        response->completionCode = IPMI_CC_INVALID_FIELD_REQUEST;
        return outPayload;
    }

    sol::Manager::get().updateSOLParameter(ipmi::convertCurrentChannelNum(
        ipmi::currentChNum, getInterfaceIndex()));
    if (!sol::Manager::get().enable)
    {
        response->completionCode = IPMI_CC_PAYLOAD_TYPE_DISABLED;
        return outPayload;
    }

    // Only one instance of SOL is currently supported.
    if (request->payloadInstance != 1)
    {
        response->completionCode = IPMI_CC_INVALID_FIELD_REQUEST;
        return outPayload;
    }

    auto session = session::Manager::get().getSession(handler->sessionID);

    if (!request->encryption && session->isCryptAlgoEnabled())
    {
        response->completionCode = IPMI_CC_PAYLOAD_WITHOUT_ENCRYPTION;
        return outPayload;
    }

    // Is SOL Payload enabled for this user & channel.
    auto userId = ipmi::ipmiUserGetUserId(session->userName);
    ipmi::PayloadAccess payloadAccess = {};
    if ((ipmi::ipmiUserGetUserPayloadAccess(session->channelNum(), userId,
                                            payloadAccess) != IPMI_CC_OK) ||
        !(payloadAccess.stdPayloadEnables1[static_cast<uint8_t>(
            message::PayloadType::SOL)]))
    {
        response->completionCode = IPMI_CC_PAYLOAD_TYPE_DISABLED;
        return outPayload;
    }

    auto status = sol::Manager::get().isPayloadActive(request->payloadInstance);
    if (status)
    {
        response->completionCode = IPMI_CC_PAYLOAD_ALREADY_ACTIVE;
        return outPayload;
    }

    // Set the current command's socket channel to the session
    handler->setChannelInSession();

    // Start the SOL payload
    try
    {
        sol::Manager::get().startPayloadInstance(request->payloadInstance,
                                                 handler->sessionID);
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to start SOL payload: {ERROR}", "ERROR", e);
        response->completionCode = IPMI_CC_UNSPECIFIED_ERROR;
        return outPayload;
    }

    response->inPayloadSize = endian::to_ipmi<uint16_t>(MAX_PAYLOAD_SIZE);
    response->outPayloadSize = endian::to_ipmi<uint16_t>(MAX_PAYLOAD_SIZE);
    response->portNum = endian::to_ipmi<uint16_t>(IPMI_STD_PORT);

    // VLAN addressing is not used
    response->vlanNum = 0xFFFF;

    return outPayload;
}

std::vector<uint8_t>
    deactivatePayload(const std::vector<uint8_t>& inPayload,
                      std::shared_ptr<message::Handler>& /* handler */)
{
    auto request =
        reinterpret_cast<const DeactivatePayloadRequest*>(inPayload.data());
    if (inPayload.size() != sizeof(*request))
    {
        std::vector<uint8_t> errorPayload{IPMI_CC_REQ_DATA_LEN_INVALID};
        return errorPayload;
    }

    std::vector<uint8_t> outPayload(sizeof(DeactivatePayloadResponse));
    auto response =
        reinterpret_cast<DeactivatePayloadResponse*>(outPayload.data());
    response->completionCode = IPMI_CC_OK;

    // SOL is the payload currently supported for deactivation
    if (static_cast<uint8_t>(message::PayloadType::SOL) != request->payloadType)
    {
        response->completionCode = IPMI_CC_INVALID_FIELD_REQUEST;
        return outPayload;
    }

    // Only one instance of SOL is supported
    if (request->payloadInstance != 1)
    {
        response->completionCode = IPMI_CC_INVALID_FIELD_REQUEST;
        return outPayload;
    }

    auto status = sol::Manager::get().isPayloadActive(request->payloadInstance);
    if (!status)
    {
        response->completionCode = IPMI_CC_PAYLOAD_DEACTIVATED;
        return outPayload;
    }

    try
    {
        auto& context =
            sol::Manager::get().getContext(request->payloadInstance);
        auto sessionID = context.sessionID;

        sol::Manager::get().stopPayloadInstance(request->payloadInstance);

        try
        {
            activating(request->payloadInstance, sessionID);
        }
        catch (const std::exception& e)
        {
            lg2::info("Failed to call the activating method: {ERROR}", "ERROR",
                      e);
            /*
             * In case session has been closed (like in the case of inactivity
             * timeout), then activating function would throw an exception,
             * since sessionID is not found. IPMI success completion code is
             * returned, since the session is closed.
             */
            return outPayload;
        }
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to call the getContext method: {ERROR}", "ERROR", e);
        response->completionCode = IPMI_CC_UNSPECIFIED_ERROR;
        return outPayload;
    }

    return outPayload;
}

std::vector<uint8_t>
    getPayloadStatus(const std::vector<uint8_t>& inPayload,
                     std::shared_ptr<message::Handler>& /* handler */)
{
    auto request =
        reinterpret_cast<const GetPayloadStatusRequest*>(inPayload.data());
    if (inPayload.size() != sizeof(*request))
    {
        std::vector<uint8_t> errorPayload{IPMI_CC_REQ_DATA_LEN_INVALID};
        return errorPayload;
    }

    std::vector<uint8_t> outPayload(sizeof(GetPayloadStatusResponse));
    auto response =
        reinterpret_cast<GetPayloadStatusResponse*>(outPayload.data());

    // SOL is the payload currently supported for payload status
    if (static_cast<uint8_t>(message::PayloadType::SOL) != request->payloadType)
    {
        response->completionCode = IPMI_CC_UNSPECIFIED_ERROR;
        return outPayload;
    }

    response->completionCode = IPMI_CC_OK;

    constexpr size_t maxSolPayloadInstances = 1;
    response->capacity = maxSolPayloadInstances;

    // Currently we support only one SOL session
    response->instance1 = sol::Manager::get().isPayloadActive(1);

    return outPayload;
}

std::vector<uint8_t>
    getPayloadInfo(const std::vector<uint8_t>& inPayload,
                   std::shared_ptr<message::Handler>& /* handler */)
{
    auto request =
        reinterpret_cast<const GetPayloadInfoRequest*>(inPayload.data());

    if (inPayload.size() != sizeof(*request))
    {
        std::vector<uint8_t> errorPayload{IPMI_CC_REQ_DATA_LEN_INVALID};
        return errorPayload;
    }

    std::vector<uint8_t> outPayload(sizeof(GetPayloadInfoResponse));
    auto response =
        reinterpret_cast<GetPayloadInfoResponse*>(outPayload.data());

    // SOL is the payload currently supported for payload status & only one
    // instance of SOL is supported.
    if (static_cast<uint8_t>(message::PayloadType::SOL) !=
            request->payloadType ||
        request->payloadInstance != 1)
    {
        response->completionCode = IPMI_CC_INVALID_FIELD_REQUEST;
        return outPayload;
    }
    auto status = sol::Manager::get().isPayloadActive(request->payloadInstance);

    if (status)
    {
        auto& context =
            sol::Manager::get().getContext(request->payloadInstance);
        response->sessionID = context.sessionID;
    }
    else
    {
        // No active payload - return session id as 0
        response->sessionID = 0;
    }
    response->completionCode = IPMI_CC_OK;
    return outPayload;
}

} // namespace command

} // namespace sol
