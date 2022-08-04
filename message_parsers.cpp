#include "message_parsers.hpp"

#include "endian.hpp"
#include "main.hpp"
#include "message.hpp"
#include "sessions_manager.hpp"

#include <memory>

namespace message
{

namespace parser
{

std::tuple<std::shared_ptr<Message>, SessionHeader>
    unflatten(std::vector<uint8_t>& inPacket)
{
    // Check if the packet has atleast the size of the RMCP Header
    if (inPacket.size() < sizeof(RmcpHeader_t))
    {
        throw std::runtime_error("RMCP Header missing");
    }

    auto rmcpHeaderPtr = reinterpret_cast<RmcpHeader_t*>(inPacket.data());

    // Verify if the fields in the RMCP header conforms to the specification
    if ((rmcpHeaderPtr->version != RMCP_VERSION) ||
        (rmcpHeaderPtr->rmcpSeqNum != RMCP_SEQ) ||
        (rmcpHeaderPtr->classOfMsg < static_cast<uint8_t>(ClassOfMsg::ASF) &&
         rmcpHeaderPtr->classOfMsg > static_cast<uint8_t>(ClassOfMsg::OEM)))
    {
        throw std::runtime_error("RMCP Header is invalid");
    }

    if (rmcpHeaderPtr->classOfMsg == static_cast<uint8_t>(ClassOfMsg::ASF))
    {
#ifndef RMCP_PING
        throw std::runtime_error("RMCP Ping is not supported");
#else
        return std::make_tuple(asfparser::unflatten(inPacket),
                               SessionHeader::IPMI15);
#endif // RMCP_PING
    }

    auto sessionHeaderPtr = reinterpret_cast<BasicHeader_t*>(inPacket.data());

    // Read the Session Header and invoke the parser corresponding to the
    // header type
    switch (static_cast<SessionHeader>(sessionHeaderPtr->format.formatType))
    {
        case SessionHeader::IPMI15:
        {
            return std::make_tuple(ipmi15parser::unflatten(inPacket),
                                   SessionHeader::IPMI15);
        }
        case SessionHeader::IPMI20:
        {
            return std::make_tuple(ipmi20parser::unflatten(inPacket),
                                   SessionHeader::IPMI20);
        }
        default:
        {
            throw std::runtime_error("Invalid Session Header");
        }
    }
}

std::vector<uint8_t> flatten(const std::shared_ptr<Message>& outMessage,
                             SessionHeader authType,
                             const std::shared_ptr<session::Session>& session)
{
    // Call the flatten routine based on the header type
    switch (authType)
    {
        case SessionHeader::IPMI15:
        {
            return ipmi15parser::flatten(outMessage, session);
        }
        case SessionHeader::IPMI20:
        {
            return ipmi20parser::flatten(outMessage, session);
        }
        default:
        {
            return {};
        }
    }
}

} // namespace parser

namespace ipmi15parser
{

std::shared_ptr<Message> unflatten(std::vector<uint8_t>& inPacket)
{
    if (inPacket.size() < sizeof(SessionHeader_t))
    {
        throw std::runtime_error("IPMI1.5 Session Header Missing");
    }

    auto header = reinterpret_cast<SessionHeader_t*>(inPacket.data());

    uint32_t sessionID = endian::from_ipmi(header->sessId);
    if (sessionID != session::sessionZero)
    {
        throw std::runtime_error("IPMI1.5 session packets are unsupported");
    }

    auto message = std::make_shared<Message>();

    message->payloadType = PayloadType::IPMI;
    message->bmcSessionID = session::sessionZero;
    message->sessionSeqNum = endian::from_ipmi(header->sessSeqNum);
    message->isPacketEncrypted = false;
    message->isPacketAuthenticated = false;
    message->rmcpMsgClass =
        static_cast<ClassOfMsg>(header->base.rmcp.classOfMsg);

    // Confirm the number of data bytes received correlates to
    // the packet length in the header
    size_t payloadLen = header->payloadLength;
    if ((payloadLen == 0) || (inPacket.size() < (sizeof(*header) + payloadLen)))
    {
        throw std::runtime_error("Invalid data length");
    }

    (message->payload)
        .assign(inPacket.data() + sizeof(SessionHeader_t),
                inPacket.data() + sizeof(SessionHeader_t) + payloadLen);

    return message;
}

std::vector<uint8_t>
    flatten(const std::shared_ptr<Message>& outMessage,
            const std::shared_ptr<session::Session>& /* session */)
{
    std::vector<uint8_t> packet(sizeof(SessionHeader_t));

    // Insert Session Header into the Packet
    auto header = reinterpret_cast<SessionHeader_t*>(packet.data());
    header->base.rmcp.version = parser::RMCP_VERSION;
    header->base.rmcp.reserved = 0x00;
    header->base.rmcp.rmcpSeqNum = parser::RMCP_SEQ;
    header->base.rmcp.classOfMsg = static_cast<uint8_t>(ClassOfMsg::IPMI);
    header->base.format.formatType =
        static_cast<uint8_t>(parser::SessionHeader::IPMI15);
    header->sessSeqNum = 0;
    header->sessId = endian::to_ipmi(outMessage->rcSessionID);

    header->payloadLength = static_cast<uint8_t>(outMessage->payload.size());

    // Insert the Payload into the Packet
    packet.insert(packet.end(), outMessage->payload.begin(),
                  outMessage->payload.end());

    // Insert the Session Trailer
    packet.resize(packet.size() + sizeof(SessionTrailer_t));
    auto trailer =
        reinterpret_cast<SessionTrailer_t*>(packet.data() + packet.size());
    trailer->legacyPad = 0x00;

    return packet;
}

} // namespace ipmi15parser

namespace ipmi20parser
{

std::shared_ptr<Message> unflatten(std::vector<uint8_t>& inPacket)
{
    // Check if the packet has atleast the Session Header
    if (inPacket.size() < sizeof(SessionHeader_t))
    {
        throw std::runtime_error("IPMI2.0 Session Header Missing");
    }

    auto header = reinterpret_cast<SessionHeader_t*>(inPacket.data());

    uint32_t sessionID = endian::from_ipmi(header->sessId);

    auto session = session::Manager::get().getSession(sessionID);
    if (!session)
    {
        throw std::runtime_error("RMCP+ message from unknown session");
    }

    auto message = std::make_shared<Message>();

    message->payloadType = static_cast<PayloadType>(header->payloadType & 0x3F);
    message->bmcSessionID = sessionID;
    message->sessionSeqNum = endian::from_ipmi(header->sessSeqNum);
    message->isPacketEncrypted =
        ((header->payloadType & PAYLOAD_ENCRYPT_MASK) ? true : false);
    message->isPacketAuthenticated =
        ((header->payloadType & PAYLOAD_AUTH_MASK) ? true : false);
    message->rmcpMsgClass =
        static_cast<ClassOfMsg>(header->base.rmcp.classOfMsg);

    // Confirm the number of data bytes received correlates to
    // the packet length in the header
    size_t payloadLen = endian::from_ipmi(header->payloadLength);
    if ((payloadLen == 0) || (inPacket.size() < (sizeof(*header) + payloadLen)))
    {
        throw std::runtime_error("Invalid data length");
    }

    bool integrityMismatch =
        session->isIntegrityAlgoEnabled() && !message->isPacketAuthenticated;
    bool encryptMismatch =
        session->isCryptAlgoEnabled() && !message->isPacketEncrypted;

    if (sessionID != session::sessionZero &&
        (integrityMismatch || encryptMismatch))
    {
        throw std::runtime_error("unencrypted or unauthenticated message");
    }

    if (message->isPacketAuthenticated)
    {
        if (!(internal::verifyPacketIntegrity(inPacket, message, payloadLen,
                                              session)))
        {
            throw std::runtime_error("Packet Integrity check failed");
        }
    }

    // Decrypt the payload if the payload is encrypted
    if (message->isPacketEncrypted)
    {
        // Assign the decrypted payload to the IPMI Message
        message->payload =
            internal::decryptPayload(inPacket, message, payloadLen, session);
    }
    else
    {
        message->payload.assign(inPacket.begin() + sizeof(SessionHeader_t),
                                inPacket.begin() + sizeof(SessionHeader_t) +
                                    payloadLen);
    }

    return message;
}

std::vector<uint8_t> flatten(const std::shared_ptr<Message>& outMessage,
                             const std::shared_ptr<session::Session>& session)
{
    std::vector<uint8_t> packet(sizeof(SessionHeader_t));

    SessionHeader_t* header = reinterpret_cast<SessionHeader_t*>(packet.data());
    header->base.rmcp.version = parser::RMCP_VERSION;
    header->base.rmcp.reserved = 0x00;
    header->base.rmcp.rmcpSeqNum = parser::RMCP_SEQ;
    header->base.rmcp.classOfMsg = static_cast<uint8_t>(ClassOfMsg::IPMI);
    header->base.format.formatType =
        static_cast<uint8_t>(parser::SessionHeader::IPMI20);
    header->payloadType = static_cast<uint8_t>(outMessage->payloadType);
    header->sessId = endian::to_ipmi(outMessage->rcSessionID);

    // Add session sequence number
    internal::addSequenceNumber(packet, session);

    size_t payloadLen = 0;

    // Encrypt the payload if needed
    if (outMessage->isPacketEncrypted)
    {
        header->payloadType |= PAYLOAD_ENCRYPT_MASK;
        auto cipherPayload = internal::encryptPayload(outMessage, session);
        payloadLen = cipherPayload.size();
        header->payloadLength = endian::to_ipmi<uint16_t>(cipherPayload.size());

        // Insert the encrypted payload into the outgoing IPMI packet
        packet.insert(packet.end(), cipherPayload.begin(), cipherPayload.end());
    }
    else
    {
        header->payloadLength =
            endian::to_ipmi<uint16_t>(outMessage->payload.size());
        payloadLen = outMessage->payload.size();

        // Insert the Payload into the Packet
        packet.insert(packet.end(), outMessage->payload.begin(),
                      outMessage->payload.end());
    }

    if (outMessage->isPacketAuthenticated)
    {
        header = reinterpret_cast<SessionHeader_t*>(packet.data());
        header->payloadType |= PAYLOAD_AUTH_MASK;
        internal::addIntegrityData(packet, outMessage, payloadLen, session);
    }

    return packet;
}

namespace internal
{

void addSequenceNumber(std::vector<uint8_t>& packet,
                       const std::shared_ptr<session::Session>& session)
{
    SessionHeader_t* header = reinterpret_cast<SessionHeader_t*>(packet.data());

    if (header->sessId == session::sessionZero)
    {
        header->sessSeqNum = 0x00;
    }
    else
    {
        auto seqNum = session->sequenceNums.increment();
        header->sessSeqNum = endian::to_ipmi(seqNum);
    }
}

bool verifyPacketIntegrity(const std::vector<uint8_t>& packet,
                           const std::shared_ptr<Message>& /* message */,
                           size_t payloadLen,
                           const std::shared_ptr<session::Session>& session)
{
    /*
     * Padding bytes are added to cause the number of bytes in the data range
     * covered by the AuthCode(Integrity Data) field to be a multiple of 4 bytes
     * .If present each integrity Pad byte is set to FFh. The following logic
     * calculates the number of padding bytes added in the IPMI packet.
     */
    auto paddingLen = 4 - ((payloadLen + 2) & 3);

    auto sessTrailerPos = sizeof(SessionHeader_t) + payloadLen + paddingLen;

    // verify packet size includes trailer struct starts at sessTrailerPos
    if (packet.size() < (sessTrailerPos + sizeof(SessionTrailer_t)))
    {
        return false;
    }

    auto trailer = reinterpret_cast<const SessionTrailer_t*>(packet.data() +
                                                             sessTrailerPos);

    // Check trailer->padLength against paddingLen, both should match up,
    // return false if the lengths don't match
    if (trailer->padLength != paddingLen)
    {
        return false;
    }

    auto integrityAlgo = session->getIntegrityAlgo();

    // Check if Integrity data length is as expected, check integrity data
    // length is same as the length expected for the Integrity Algorithm that
    // was negotiated during the session open process.
    if ((packet.size() - sessTrailerPos - sizeof(SessionTrailer_t)) !=
        integrityAlgo->authCodeLength)
    {
        return false;
    }

    auto integrityIter = packet.cbegin();
    std::advance(integrityIter, sessTrailerPos + sizeof(SessionTrailer_t));

    // The integrity data is calculated from the AuthType/Format field up to and
    // including the field that immediately precedes the AuthCode field itself.
    size_t length = packet.size() - integrityAlgo->authCodeLength -
                    message::parser::RMCP_SESSION_HEADER_SIZE;

    return integrityAlgo->verifyIntegrityData(packet, length, integrityIter,
                                              packet.cend());
}

void addIntegrityData(std::vector<uint8_t>& packet,
                      const std::shared_ptr<Message>& /* message */,
                      size_t payloadLen,
                      const std::shared_ptr<session::Session>& session)
{
    // The following logic calculates the number of padding bytes to be added to
    // IPMI packet. If needed each integrity Pad byte is set to FFh.
    auto paddingLen = 4 - ((payloadLen + 2) & 3);
    packet.insert(packet.end(), paddingLen, 0xFF);

    packet.resize(packet.size() + sizeof(SessionTrailer_t));

    auto trailer = reinterpret_cast<SessionTrailer_t*>(
        packet.data() + packet.size() - sizeof(SessionTrailer_t));

    trailer->padLength = paddingLen;
    trailer->nextHeader = parser::RMCP_MESSAGE_CLASS_IPMI;

    auto integrityData =
        session->getIntegrityAlgo()->generateIntegrityData(packet);

    packet.insert(packet.end(), integrityData.begin(), integrityData.end());
}

std::vector<uint8_t>
    decryptPayload(const std::vector<uint8_t>& packet,
                   const std::shared_ptr<Message>& /* message */,
                   size_t payloadLen,
                   const std::shared_ptr<session::Session>& session)
{
    return session->getCryptAlgo()->decryptPayload(
        packet, sizeof(SessionHeader_t), payloadLen);
}

std::vector<uint8_t>
    encryptPayload(const std::shared_ptr<Message>& message,
                   const std::shared_ptr<session::Session>& session)
{
    return session->getCryptAlgo()->encryptPayload(message->payload);
}

} // namespace internal

} // namespace ipmi20parser

#ifdef RMCP_PING
namespace asfparser
{
std::shared_ptr<Message> unflatten(std::vector<uint8_t>& inPacket)
{
    auto message = std::make_shared<Message>();

    auto header = reinterpret_cast<AsfMessagePing_t*>(inPacket.data());

    message->payloadType = PayloadType::IPMI;
    message->rmcpMsgClass = ClassOfMsg::ASF;
    message->asfMsgTag = header->msgTag;

    return message;
}

std::vector<uint8_t> flatten(uint8_t asfMsgTag)
{
    std::vector<uint8_t> packet(sizeof(AsfMessagePong_t));

    // Insert RMCP header into the Packet
    auto header = reinterpret_cast<AsfMessagePong_t*>(packet.data());
    header->ping.rmcp.version = parser::RMCP_VERSION;
    header->ping.rmcp.reserved = 0x00;
    header->ping.rmcp.rmcpSeqNum = parser::RMCP_SEQ;
    header->ping.rmcp.classOfMsg = static_cast<uint8_t>(ClassOfMsg::ASF);

    // No OEM-specific capabilities exist, therefore the second
    // IANA Enterprise Number contains the same IANA(4542)
    header->ping.iana = header->iana = endian::to_ipmi(parser::ASF_IANA);
    header->ping.msgType = static_cast<uint8_t>(RmcpMsgType::PONG);
    header->ping.msgTag = asfMsgTag;
    header->ping.reserved = 0x00;
    header->ping.dataLen =
        parser::RMCP_ASF_PONG_DATA_LEN; // as per spec 13.2.4,

    header->iana = parser::ASF_IANA;
    header->oemDefined = 0x00;
    header->suppEntities = parser::ASF_SUPP_ENT;
    header->suppInteract = parser::ASF_SUPP_INT;
    header->reserved1 = 0x00;
    header->reserved2 = 0x00;

    return packet;
}

} // namespace asfparser
#endif // RMCP_PING

} // namespace message
