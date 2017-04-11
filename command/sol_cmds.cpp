#include <phosphor-logging/log.hpp>
#include "main.hpp"
#include "sol/sol_context.hpp"
#include "sol/sol_manager.hpp"
#include "sol_cmds.hpp"

namespace sol
{

namespace command
{

using namespace phosphor::logging;

std::vector<uint8_t> payloadHandler(const std::vector<uint8_t>& inPayload,
                                    const message::Handler& handler)
{
    auto request = reinterpret_cast<const Payload*>(inPayload.data());
    auto solDataSize = inPayload.size() - sizeof(Payload);

    Buffer charData(solDataSize);
    if( solDataSize > 0)
    {
        std::copy_n(inPayload.data() + sizeof(Payload),
                    solDataSize,
                    charData.begin());
    }

    try
    {
        auto& context = std::get<sol::Manager&>(singletonPool).
                getContext(handler.sessionID);

        context.processInboundPayload(request->packetSeqNum,
                                      request->packetAckSeqNum,
                                      request->acceptedCharCount,
                                      request->inOperation.ack,
                                      charData);
    }
    catch (std::exception& e)
    {
        log<level::ERR>(e.what());
        return std::vector<uint8_t>();
    }

    return std::vector<uint8_t>();
}

void activating(uint8_t payloadInstance, uint32_t sessionID)
{
    std::vector<uint8_t> outPayload(sizeof(ActivatingRequest));

    auto request = reinterpret_cast<ActivatingRequest*>
                    (outPayload.data());

    request->sessionState = 0;
    request->payloadInstance = payloadInstance;
    request->majorVersion = MAJOR_VERSION;
    request->minorVersion = MINOR_VERSION;

    auto session = (std::get<session::Manager&>(singletonPool).getSession(
            sessionID)).lock();

    message::Handler msgHandler(session->channelPtr, sessionID);

    msgHandler.sendUnsolicitedIPMIPayload(netfnTransport,
                                          solActivatingCmd,
                                          outPayload);
}

} // namespace command

} // namespace sol
