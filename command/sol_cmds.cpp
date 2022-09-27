#include "sol_cmds.hpp"

#include "sessions_manager.hpp"
#include "sol/sol_context.hpp"
#include "sol/sol_manager.hpp"

#include <phosphor-logging/lg2.hpp>

namespace sol
{

namespace command
{

using namespace phosphor::logging;

std::vector<uint8_t> payloadHandler(const std::vector<uint8_t>& inPayload,
                                    std::shared_ptr<message::Handler>& handler)
{
    // Check inPayload size is at least Payload
    if (inPayload.size() < sizeof(Payload))
    {
        return std::vector<uint8_t>();
    }

    auto request = reinterpret_cast<const Payload*>(inPayload.data());
    auto solDataSize = inPayload.size() - sizeof(Payload);

    std::vector<uint8_t> charData(solDataSize);
    if (solDataSize > 0)
    {
        std::copy_n(inPayload.data() + sizeof(Payload), solDataSize,
                    charData.begin());
    }

    try
    {
        auto& context = sol::Manager::get().getContext(handler->sessionID);

        context.processInboundPayload(
            request->packetSeqNum, request->packetAckSeqNum,
            request->acceptedCharCount, request->inOperation.ack,
            request->inOperation.generateBreak, charData);
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to call the getContext method: {ERROR}", "ERROR", e);
        return std::vector<uint8_t>();
    }

    return std::vector<uint8_t>();
}

void activating(uint8_t payloadInstance, uint32_t sessionID)
{
    std::vector<uint8_t> outPayload(sizeof(ActivatingRequest));

    auto request = reinterpret_cast<ActivatingRequest*>(outPayload.data());

    request->sessionState = 0;
    request->payloadInstance = payloadInstance;
    request->majorVersion = MAJOR_VERSION;
    request->minorVersion = MINOR_VERSION;

    auto session = session::Manager::get().getSession(sessionID);

    message::Handler msgHandler(session->channelPtr, sessionID);

    msgHandler.sendUnsolicitedIPMIPayload(netfnTransport, solActivatingCmd,
                                          outPayload);
}
} // namespace command

} // namespace sol
