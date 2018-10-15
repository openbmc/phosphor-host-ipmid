#include "open_session.hpp"

#include "comm_module.hpp"
#include "endian.hpp"
#include "main.hpp"

#include <iostream>

namespace command
{

std::vector<uint8_t> openSession(const std::vector<uint8_t>& inPayload,
                                 const message::Handler& handler)
{

    std::vector<uint8_t> outPayload(sizeof(OpenSessionResponse));
    auto request =
        reinterpret_cast<const OpenSessionRequest*>(inPayload.data());
    auto response = reinterpret_cast<OpenSessionResponse*>(outPayload.data());

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
        session =
            std::get<session::Manager&>(singletonPool)
                .startSession(
                    endian::from_ipmi<>(request->remoteConsoleSessionID),
                    static_cast<session::Privilege>(request->maxPrivLevel),
                    static_cast<cipher::rakp_auth::Algorithms>(
                        request->authAlgo),
                    static_cast<cipher::integrity::Algorithms>(
                        request->intAlgo),
                    static_cast<cipher::crypt::Algorithms>(request->confAlgo));
    }
    catch (std::exception& e)
    {
        std::cerr << e.what() << "\n";
        response->status_code =
            static_cast<uint8_t>(RAKP_ReturnCode::INSUFFICIENT_RESOURCE);
        std::cerr << "openSession : Problem opening a session\n";
        return outPayload;
    }

    response->messageTag = request->messageTag;
    response->status_code = static_cast<uint8_t>(RAKP_ReturnCode::NO_ERROR);
    response->maxPrivLevel = static_cast<uint8_t>(session->curPrivLevel);
    response->remoteConsoleSessionID = request->remoteConsoleSessionID;
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
    session->state = session::State::SETUP_IN_PROGRESS;
    return outPayload;
}

} // namespace command
