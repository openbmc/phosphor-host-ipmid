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

std::vector<uint8_t> setConfParams(const std::vector<uint8_t>& inPayload,
                                   const message::Handler& handler)
{
    std::vector<uint8_t> outPayload(sizeof(SetConfParamsResponse));
    auto request = reinterpret_cast<const SetConfParamsRequest*>
                   (inPayload.data());
    auto response = reinterpret_cast<SetConfParamsResponse*>
                    (outPayload.data());
    response->completionCode = IPMI_CC_OK;

    switch (static_cast<Parameter>(request->paramSelector))
    {
        case Parameter::PROGRESS:
        {
            uint8_t progress = request->value & progressMask;
            std::get<sol::Manager&>(singletonPool).progress = progress;
            break;
        }
        case Parameter::ENABLE:
        {
            bool enable = request->value & enableMask;
            std::get<sol::Manager&>(singletonPool).enable = enable;
            break;
        }
        case Parameter::AUTHENTICATION:
        {
            if (!request->auth.auth || !request->auth.encrypt)
            {
                response->completionCode = ipmiCCWriteReadParameter;
            }
            else if (request->auth.privilege <
                     static_cast<uint8_t>(session::Privilege::USER) ||
                     request->auth.privilege >
                     static_cast<uint8_t>(session::Privilege::OEM))
            {
                response->completionCode = IPMI_CC_INVALID_FIELD_REQUEST;
            }
            else
            {
                std::get<sol::Manager&>(singletonPool).solMinPrivilege =
                       static_cast<session::Privilege>(request->auth.privilege);
            }
            break;
        }
        case Parameter::ACCUMULATE:
        {
            using namespace std::chrono_literals;

            if (request->acc.threshold == 0)
            {
                response->completionCode = IPMI_CC_INVALID_FIELD_REQUEST;
                break;
            }

            std::get<sol::Manager&>(singletonPool).accumulateInterval =
                    request->acc.interval * sol::accIntervalFactor * 1ms;
            std::get<sol::Manager&>(singletonPool).sendThreshold =
                    request->acc.threshold;
            break;
        }
        case Parameter::RETRY:
        {
            using namespace std::chrono_literals;

            std::get<sol::Manager&>(singletonPool).retryCount =
                    request->retry.count;
            std::get<sol::Manager&>(singletonPool).retryInterval =
                    request->retry.interval * sol::retryIntervalFactor * 1ms;
            break;
        }
        case Parameter::PORT:
        {
            response->completionCode = ipmiCCWriteReadParameter;
            break;
        }
        case Parameter::NVBITRATE:
        case Parameter::VBITRATE:
        case Parameter::CHANNEL:
        default:
            response->completionCode = ipmiCCParamNotSupported;
    }

    return outPayload;
}

} // namespace command

} // namespace sol
