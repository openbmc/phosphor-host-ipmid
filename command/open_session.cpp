#include "open_session.hpp"

#include "comm_module.hpp"
#include "endian.hpp"
#include "sessions_manager.hpp"

#include <phosphor-logging/lg2.hpp>

namespace command
{

std::vector<uint8_t>
    openSession(const std::vector<uint8_t>& inPayload,
                std::shared_ptr<message::Handler>& /* handler */)
{
    auto request =
        reinterpret_cast<const OpenSessionRequest*>(inPayload.data());
    if (inPayload.size() != sizeof(*request))
    {
        std::vector<uint8_t> errorPayload{IPMI_CC_REQ_DATA_LEN_INVALID};
        return errorPayload;
    }

    std::vector<uint8_t> outPayload(sizeof(OpenSessionResponse));
    auto response = reinterpret_cast<OpenSessionResponse*>(outPayload.data());

    // Per the IPMI Spec, messageTag and remoteConsoleSessionID are always
    // returned
    response->messageTag = request->messageTag;
    response->remoteConsoleSessionID = request->remoteConsoleSessionID;

    // Check for valid Authentication Algorithms
    if (!cipher::rakp_auth::Interface::isAlgorithmSupported(
            static_cast<cipher::rakp_auth::Algorithms>(request->authAlgo)))
    {
        response->status_code =
            static_cast<uint8_t>(RAKP_ReturnCode::INVALID_AUTH_ALGO);
        return outPayload;
    }

    // Check for valid Integrity Algorithms
    if (!cipher::integrity::Interface::isAlgorithmSupported(
            static_cast<cipher::integrity::Algorithms>(request->intAlgo)))
    {
        response->status_code =
            static_cast<uint8_t>(RAKP_ReturnCode::INVALID_INTEGRITY_ALGO);
        return outPayload;
    }

    session::Privilege priv;

    // 0h in the requested maximum privilege role field indicates highest level
    // matching proposed algorithms. The maximum privilege level the session
    // can take is set to Administrator level. In the RAKP12 command sequence
    // the session maximum privilege role is set again based on the user's
    // permitted privilege level.
    if (!request->maxPrivLevel)
    {
        priv = session::Privilege::ADMIN;
    }
    else
    {
        priv = static_cast<session::Privilege>(request->maxPrivLevel);
    }

    // Check for valid Confidentiality Algorithms
    if (!cipher::crypt::Interface::isAlgorithmSupported(
            static_cast<cipher::crypt::Algorithms>(request->confAlgo)))
    {
        response->status_code =
            static_cast<uint8_t>(RAKP_ReturnCode::INVALID_CONF_ALGO);
        return outPayload;
    }

    std::shared_ptr<session::Session> session;
    try
    {
        // Start an IPMI session
        session = session::Manager::get().startSession(
            endian::from_ipmi<>(request->remoteConsoleSessionID), priv,
            static_cast<cipher::rakp_auth::Algorithms>(request->authAlgo),
            static_cast<cipher::integrity::Algorithms>(request->intAlgo),
            static_cast<cipher::crypt::Algorithms>(request->confAlgo));
    }
    catch (const std::exception& e)
    {
        response->status_code =
            static_cast<uint8_t>(RAKP_ReturnCode::INSUFFICIENT_RESOURCE);
        lg2::error("openSession : Problem opening a session: {ERROR}", "ERROR",
                   e);
        return outPayload;
    }

    response->status_code = static_cast<uint8_t>(RAKP_ReturnCode::NO_ERROR);
    response->maxPrivLevel = static_cast<uint8_t>(session->reqMaxPrivLevel);
    response->managedSystemSessionID =
        endian::to_ipmi<>(session->getBMCSessionID());

    response->authPayload = request->authPayload;
    response->authPayloadLen = request->authPayloadLen;
    response->authAlgo = request->authAlgo;

    response->intPayload = request->intPayload;
    response->intPayloadLen = request->intPayloadLen;
    response->intAlgo = request->intAlgo;

    response->confPayload = request->confPayload;
    response->confPayloadLen = request->confPayloadLen;
    response->confAlgo = request->confAlgo;

    session->updateLastTransactionTime();

    // Session state is Setup in progress
    session->state(static_cast<uint8_t>(session::State::setupInProgress));
    return outPayload;
}

} // namespace command
