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

std::vector<uint8_t> payloadHandler(std::vector<uint8_t>& inPayload,
                                    const message::Handler& handler)
{
    auto request = reinterpret_cast<Payload*>(inPayload.data());

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

} // namespace command

} // namespace sol
