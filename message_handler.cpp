#include "message_handler.hpp"

#include "command_table.hpp"
#include "main.hpp"
#include "message.hpp"
#include "message_parsers.hpp"
#include "sessions_manager.hpp"

#include <sys/socket.h>

#include <phosphor-logging/lg2.hpp>

#include <memory>
#include <string>
#include <vector>

namespace message
{

bool Handler::receive()
{
    std::vector<uint8_t> packet;
    auto readStatus = 0;

    // Read the packet
    std::tie(readStatus, packet) = channel->read();

    // Read of the packet failed
    if (readStatus < 0)
    {
        lg2::error("Error in Read status: {STATUS}", "STATUS", readStatus);
        return false;
    }

    // Unflatten the packet
    std::tie(inMessage, sessionHeader) = parser::unflatten(packet);

    return true;
}

void Handler::updSessionData(std::shared_ptr<Message>& inMessage)
{
    session = session::Manager::get().getSession(inMessage->bmcSessionID);

    sessionID = inMessage->bmcSessionID;
    inMessage->rcSessionID = session->getRCSessionID();
    session->updateLastTransactionTime();
    session->channelPtr = channel;
    session->remotePort(channel->getPort());
    uint32_t ipAddr = 0;
    channel->getRemoteAddress(ipAddr);
    session->remoteIPAddr(ipAddr);
}

Handler::~Handler()
{
    try
    {
#ifdef RMCP_PING
        if (ClassOfMsg::ASF == inMessage->rmcpMsgClass)
        {
            sendASF();
        }
        else
#endif // RMCP_PING
        {
            if (outPayload)
            {
                std::shared_ptr<Message> outMessage =
                    inMessage->createResponse(*outPayload);
                if (!outMessage)
                {
                    return;
                }
                send(outMessage);
            }
        }
    }
    catch (const std::exception& e)
    {
        // send failed, most likely due to a session closure
        lg2::info("Async RMCP+ reply failed: {ERROR}", "ERROR", e);
    }
}

void Handler::processIncoming()
{
    // Read the incoming IPMI packet
    if (!receive())
    {
        return;
    }

#ifdef RMCP_PING
    // Execute the Command, possibly asynchronously
    if (ClassOfMsg::ASF != inMessage->rmcpMsgClass)
#endif // RMCP_PING
    {
        updSessionData(inMessage);
        executeCommand();
    }

    // send happens during the destructor if a payload was set
}

void Handler::executeCommand()
{
    // Get the CommandID to map into the command table
    auto command = inMessage->getCommand();
    if (inMessage->payloadType == PayloadType::IPMI)
    {
        // Process PayloadType::IPMI only if ipmi is enabled or for sessionless
        // or for session establisbment command
        if (this->sessionID == session::sessionZero ||
            session->sessionUserPrivAccess.ipmiEnabled)
        {
            if (inMessage->payload.size() <
                (sizeof(LAN::header::Request) + sizeof(LAN::trailer::Request)))
            {
                return;
            }

            auto start =
                inMessage->payload.begin() + sizeof(LAN::header::Request);
            auto end = inMessage->payload.end() - sizeof(LAN::trailer::Request);
            std::vector<uint8_t> inPayload(start, end);
            command::Table::get().executeCommand(command, inPayload,
                                                 shared_from_this());
        }
        else
        {
            std::vector<uint8_t> payload{IPMI_CC_INSUFFICIENT_PRIVILEGE};
            outPayload = std::move(payload);
        }
    }
    else
    {
        command::Table::get().executeCommand(command, inMessage->payload,
                                             shared_from_this());
    }
}

void Handler::writeData(const std::vector<uint8_t>& packet)
{
    auto writeStatus = channel->write(packet);
    if (writeStatus < 0)
    {
        throw std::runtime_error("Error in writing to socket");
    }
}

#ifdef RMCP_PING
void Handler::sendASF()
{
    // Flatten the packet
    auto packet = asfparser::flatten(inMessage->asfMsgTag);

    // Write the packet
    writeData(packet);
}
#endif // RMCP_PING

void Handler::send(std::shared_ptr<Message> outMessage)
{
    // Flatten the packet
    auto packet = parser::flatten(outMessage, sessionHeader, session);

    // Write the packet
    writeData(packet);
}

void Handler::setChannelInSession() const
{
    session->channelPtr = channel;
}

void Handler::sendSOLPayload(const std::vector<uint8_t>& input)
{
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
