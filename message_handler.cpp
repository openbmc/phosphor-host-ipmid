#include "message_handler.hpp"

#include "command_table.hpp"
#include "main.hpp"
#include "message.hpp"
#include "message_parsers.hpp"
#include "sessions_manager.hpp"

#include <sys/socket.h>

#include <memory>
#include <phosphor-logging/log.hpp>
#include <string>
#include <vector>

using namespace phosphor::logging;

namespace message
{

std::shared_ptr<Message> Handler::receive()
{
    std::vector<uint8_t> packet;
    auto readStatus = 0;

    // Read the packet
    std::tie(readStatus, packet) = channel->read();

    // Read of the packet failed
    if (readStatus < 0)
    {
        log<level::ERR>("Error in Read", entry("STATUS=%x", readStatus));
        return nullptr;
    }

    // Unflatten the packet
    std::shared_ptr<Message> message;
    std::tie(message, sessionHeader) = parser::unflatten(packet);

    auto session = std::get<session::Manager&>(singletonPool)
                       .getSession(message->bmcSessionID);

    sessionID = message->bmcSessionID;
    message->rcSessionID = session->getRCSessionID();
    session->updateLastTransactionTime();

    return message;
}

std::shared_ptr<Message>
    Handler::executeCommand(std::shared_ptr<Message> inMessage)
{
    // Get the CommandID to map into the command table
    auto command = inMessage->getCommand();
    std::vector<uint8_t> output{};

    if (inMessage->payloadType == PayloadType::IPMI)
    {
        if (inMessage->payload.size() <
            (sizeof(LAN::header::Request) + sizeof(LAN::trailer::Request)))
        {
            return nullptr;
        }

        auto start = inMessage->payload.begin() + sizeof(LAN::header::Request);
        auto end = inMessage->payload.end() - sizeof(LAN::trailer::Request);
        std::vector<uint8_t> inPayload(start, end);

        output = std::get<command::Table&>(singletonPool)
                     .executeCommand(command, inPayload, *this);
    }
    else
    {
        output = std::get<command::Table&>(singletonPool)
                     .executeCommand(command, inMessage->payload, *this);
    }
    return inMessage->createResponse(output);
}

void Handler::send(std::shared_ptr<Message> outMessage)
{
    auto session =
        std::get<session::Manager&>(singletonPool).getSession(sessionID);

    // Flatten the packet
    auto packet = parser::flatten(outMessage, sessionHeader, session);

    // Write the packet
    auto writeStatus = channel->write(packet);
    if (writeStatus < 0)
    {
        throw std::runtime_error("Error in writing to socket");
    }
}

void Handler::setChannelInSession() const
{
    auto session =
        std::get<session::Manager&>(singletonPool).getSession(sessionID);

    session->channelPtr = channel;
}

void Handler::sendSOLPayload(const std::vector<uint8_t>& input)
{
    auto session =
        std::get<session::Manager&>(singletonPool).getSession(sessionID);

    auto outMessage = std::make_shared<Message>();
    outMessage->payloadType = PayloadType::SOL;
    outMessage->payload = input;
    outMessage->isPacketEncrypted = session->isCryptAlgoEnabled();
    outMessage->isPacketAuthenticated = session->isIntegrityAlgoEnabled();
    outMessage->rcSessionID = session->getRCSessionID();
    outMessage->bmcSessionID = sessionID;

    send(outMessage);
}

void Handler::sendUnsolicitedIPMIPayload(uint8_t netfn, uint8_t cmd,
                                         const std::vector<uint8_t>& output)
{
    auto session =
        std::get<session::Manager&>(singletonPool).getSession(sessionID);

    auto outMessage = std::make_shared<Message>();
    outMessage->payloadType = PayloadType::IPMI;
    outMessage->isPacketEncrypted = session->isCryptAlgoEnabled();
    outMessage->isPacketAuthenticated = session->isIntegrityAlgoEnabled();
    outMessage->rcSessionID = session->getRCSessionID();
    outMessage->bmcSessionID = sessionID;

    outMessage->payload.resize(sizeof(LAN::header::Request) + output.size() +
                               sizeof(LAN::trailer::Request));

    auto respHeader =
        reinterpret_cast<LAN::header::Request*>(outMessage->payload.data());

    // Add IPMI LAN Message Request Header
    respHeader->rsaddr = LAN::requesterBMCAddress;
    respHeader->netfn = (netfn << 0x02);
    respHeader->cs = crc8bit(&(respHeader->rsaddr), 2);
    respHeader->rqaddr = LAN::responderBMCAddress;
    respHeader->rqseq = 0;
    respHeader->cmd = cmd;

    auto assembledSize = sizeof(LAN::header::Request);

    // Copy the output by the execution of the command
    std::copy(output.begin(), output.end(),
              outMessage->payload.begin() + assembledSize);
    assembledSize += output.size();

    // Add the IPMI LAN Message Trailer
    auto trailer = reinterpret_cast<LAN::trailer::Request*>(
        outMessage->payload.data() + assembledSize);

    // Calculate the checksum for the field rqaddr in the header to the
    // command data, 3 corresponds to size of the fields before rqaddr( rsaddr,
    // netfn, cs).
    trailer->checksum = crc8bit(&respHeader->rqaddr, assembledSize - 3);

    send(outMessage);
}

} // namespace message
