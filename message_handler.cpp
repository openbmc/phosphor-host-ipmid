#include "message_handler.hpp"

#include <sys/socket.h>

#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "command_table.hpp"
#include "main.hpp"
#include "message.hpp"
#include "message_parsers.hpp"
#include "sessions_manager.hpp"

namespace message
{

std::unique_ptr<Message> Handler::receive()
{
    std::vector<uint8_t> packet;
    auto readStatus = 0;

    // Read the packet
    std::tie(readStatus, packet) = channel->read();

    // Read of the packet failed
    if (readStatus < 0)
    {
        std::cerr << "E> Error in Read : " << std::hex << readStatus << "\n";
        return nullptr;
    }

    // Unflatten the packet
    std::unique_ptr<Message> message;
    std::tie(message, sessionHeader) = parser::unflatten(packet);

    auto session = (std::get<session::Manager&>(singletonPool).getSession(
                   message->bmcSessionID)).lock();

    sessionID = message->bmcSessionID;
    message->rcSessionID = session->getRCSessionID();
    session->updateLastTransactionTime();

    return message;
}

template<>
std::unique_ptr<Message> Handler::createResponse<PayloadType::IPMI>(
        std::vector<uint8_t>& output, Message& inMessage)
{
    auto outMessage = std::make_unique<Message>();
    outMessage->payloadType = PayloadType::IPMI;

    outMessage->payload.resize(sizeof(LAN::header::Response) +
                               output.size() +
                               sizeof(LAN::trailer::Response));

    auto reqHeader = reinterpret_cast<LAN::header::Request*>
                     (inMessage.payload.data());
    auto respHeader = reinterpret_cast<LAN::header::Response*>
                      (outMessage->payload.data());

    // Add IPMI LAN Message Response Header
    respHeader->rqaddr = reqHeader->rqaddr;
    respHeader->netfn  = reqHeader->netfn | 0x04;
    respHeader->cs     = crc8bit(&(respHeader->rqaddr), 2);
    respHeader->rsaddr = reqHeader->rsaddr;
    respHeader->rqseq  = reqHeader->rqseq;
    respHeader->cmd    = reqHeader->cmd;

    auto assembledSize = sizeof(LAN::header::Response);

    // Copy the output by the execution of the command
    std::copy(output.begin(), output.end(),
              outMessage->payload.begin() + assembledSize);
    assembledSize += output.size();

    // Add the IPMI LAN Message Trailer
    auto trailer = reinterpret_cast<LAN::trailer::Response*>
                   (outMessage->payload.data() + assembledSize);
    trailer->checksum = crc8bit(&respHeader->rsaddr, assembledSize - 3);

    return outMessage;
}

std::unique_ptr<Message> Handler::executeCommand(Message& inMessage)
{
    // Get the CommandID to map into the command table
    auto command = getCommand(inMessage);
    std::vector<uint8_t> output{};

    if (inMessage.payloadType == PayloadType::IPMI)
    {
        if (inMessage.payload.size() < (sizeof(LAN::header::Request) +
                                        sizeof(LAN::trailer::Request)))
        {
            return nullptr;
        }

        auto start = inMessage.payload.begin() + sizeof(LAN::header::Request);
        auto end = inMessage.payload.end() - sizeof(LAN::trailer::Request);
        std::vector<uint8_t> inPayload(start, end);

        output = std::get<command::Table&>(singletonPool).executeCommand(
                     command,
                     inPayload,
                     *this);
    }
    else
    {
        output = std::get<command::Table&>(singletonPool).executeCommand(
                     command,
                     inMessage.payload,
                     *this);
    }

    std::unique_ptr<Message> outMessage = nullptr;

    switch (inMessage.payloadType)
    {
        case PayloadType::IPMI:
            outMessage = createResponse<PayloadType::IPMI>(output, inMessage);
            break;
        case PayloadType::OPEN_SESSION_REQUEST:
            outMessage = createResponse<PayloadType::OPEN_SESSION_RESPONSE>(
                             output, inMessage);
            break;
        case PayloadType::RAKP1:
            outMessage = createResponse<PayloadType::RAKP2>(output, inMessage);
            break;
        case PayloadType::RAKP3:
            outMessage = createResponse<PayloadType::RAKP4>(output, inMessage);
            break;
        default:
            break;
    }

    outMessage->isPacketEncrypted = inMessage.isPacketEncrypted;
    outMessage->isPacketAuthenticated = inMessage.isPacketAuthenticated;
    outMessage->rcSessionID = inMessage.rcSessionID;
    outMessage->bmcSessionID = inMessage.bmcSessionID;

    return outMessage;
}

uint32_t Handler::getCommand(Message& message)
{
    uint32_t command = 0 ;

    command |= (static_cast<uint8_t>(message.payloadType) << 16);
    if (message.payloadType == PayloadType::IPMI)
    {
        command |= ((reinterpret_cast<LAN::header::Request*>
                     (message.payload.data()))->netfn) << 8;
        command |= (reinterpret_cast<LAN::header::Request*>
                    (message.payload.data()))->cmd;
    }

    return command;
}

int Handler::send(Message& outMessage)
{
    auto session = (std::get<session::Manager&>(singletonPool).getSession(
                    sessionID)).lock();

    // Flatten the packet
    auto packet = parser::flatten(outMessage, sessionHeader, *session);

    // Read the packet
    auto writeStatus = channel->write(packet);
    if (writeStatus < 0)
    {
        std::cerr << "E> Error in writing : " << std::hex << writeStatus
                  << "\n";
    }

    return writeStatus;
}

} //namespace message

