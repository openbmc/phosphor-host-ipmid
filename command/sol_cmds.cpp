#include "sol_cmds.hpp"

#include "sessions_manager.hpp"
#include "sol/sol_context.hpp"
#include "sol/sol_manager.hpp"

#include <phosphor-logging/log.hpp>

namespace sol
{

namespace command
{

using namespace phosphor::logging;

std::vector<uint8_t> payloadHandler(const std::vector<uint8_t>& inPayload,
                                    const message::Handler& handler)
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
        auto& context = sol::Manager::get().getContext(handler.sessionID);

        context.processInboundPayload(
            request->packetSeqNum, request->packetAckSeqNum,
            request->acceptedCharCount, request->inOperation.ack, charData);
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

std::vector<uint8_t> getConfParams(const std::vector<uint8_t>& inPayload,
                                   const message::Handler& handler)
{
    std::vector<uint8_t> outPayload(sizeof(GetConfParamsResponse));
    auto request =
        reinterpret_cast<const GetConfParamsRequest*>(inPayload.data());
    auto response = reinterpret_cast<GetConfParamsResponse*>(outPayload.data());
    response->completionCode = IPMI_CC_OK;
    response->paramRev = parameterRevision;

    if (request->getParamRev)
    {
        return outPayload;
    }

    switch (static_cast<Parameter>(request->paramSelector))
    {
        case Parameter::PROGRESS:
        {
            outPayload.push_back(sol::Manager::get().progress);
            break;
        }
        case Parameter::ENABLE:
        {
            outPayload.push_back(sol::Manager::get().enable);
            break;
        }
        case Parameter::AUTHENTICATION:
        {
            Auth value{0};

            value.encrypt = sol::Manager::get().forceEncrypt;
            value.auth = sol::Manager::get().forceAuth;
            value.privilege =
                static_cast<uint8_t>(sol::Manager::get().solMinPrivilege);
            auto buffer = reinterpret_cast<const uint8_t*>(&value);

            std::copy_n(buffer, sizeof(value), std::back_inserter(outPayload));
            break;
        }
        case Parameter::ACCUMULATE:
        {
            Accumulate value{0};

            value.interval = sol::Manager::get().accumulateInterval.count() /
                             sol::accIntervalFactor;
            value.threshold = sol::Manager::get().sendThreshold;
            auto buffer = reinterpret_cast<const uint8_t*>(&value);

            std::copy_n(buffer, sizeof(value), std::back_inserter(outPayload));
            break;
        }
        case Parameter::RETRY:
        {
            Retry value{0};

            value.count = sol::Manager::get().retryCount;
            value.interval = sol::Manager::get().retryInterval.count() /
                             sol::retryIntervalFactor;
            auto buffer = reinterpret_cast<const uint8_t*>(&value);

            std::copy_n(buffer, sizeof(value), std::back_inserter(outPayload));
            break;
        }
        case Parameter::PORT:
        {
            auto port = endian::to_ipmi<uint16_t>(IPMI_STD_PORT);
            auto buffer = reinterpret_cast<const uint8_t*>(&port);

            std::copy_n(buffer, sizeof(port), std::back_inserter(outPayload));
            break;
        }
        case Parameter::CHANNEL:
        {
            outPayload.push_back(sol::Manager::get().channel);
            break;
        }
        case Parameter::NVBITRATE:
        case Parameter::VBITRATE:
        default:
            response->completionCode = ipmiCCParamNotSupported;
    }

    return outPayload;
}

} // namespace command

} // namespace sol
