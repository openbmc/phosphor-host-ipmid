#pragma once

#include <memory>
#include <vector>

namespace message
{

enum class PayloadType : uint8_t
{
    IPMI = 0x00,
    SOL = 0x01,
    OPEN_SESSION_REQUEST = 0x10,
    OPEN_SESSION_RESPONSE = 0x11,
    RAKP1 = 0x12,
    RAKP2 = 0x13,
    RAKP3 = 0x14,
    RAKP4 = 0x15,
    INVALID = 0xFF,
};

/**
 * @struct Message
 *
 * IPMI message is data encapsulated in an IPMI Session packet. The IPMI
 * Session packets are encapsulated in RMCP packets, which are encapsulated in
 * UDP datagrams. Refer Section 13.5 of IPMI specification(IPMI Messages
 * Encapsulation Under RMCP). IPMI payload is a special class of data
 * encapsulated in an IPMI session packet.
 */
struct Message
{
    static constexpr uint32_t MESSAGE_INVALID_SESSION_ID = 0xBADBADFF;

    Message() :
        payloadType(PayloadType::INVALID),
        rcSessionID(Message::MESSAGE_INVALID_SESSION_ID),
        bmcSessionID(Message::MESSAGE_INVALID_SESSION_ID)
    {
    }

    ~Message() = default;
    Message(const Message&) = default;
    Message& operator=(const Message&) = default;
    Message(Message&&) = default;
    Message& operator=(Message&&) = default;

    bool isPacketEncrypted;     // Message's Encryption Status
    bool isPacketAuthenticated; // Message's Authentication Status
    PayloadType payloadType;    // Type of message payload (IPMI,SOL ..etc)
    uint32_t rcSessionID;       // Remote Client's Session ID
    uint32_t bmcSessionID;      // BMC's session ID
    uint32_t sessionSeqNum;     // Session Sequence Number

    /** @brief Message payload
     *
     *  “Payloads” are a capability specified for RMCP+ that enable an IPMI
     *  session to carry types of traffic that are in addition to IPMI Messages.
     *  Payloads can be ‘standard’ or ‘OEM’.Standard payload types include IPMI
     *  Messages, messages for session setup under RMCP+, and the payload for
     *  the “Serial Over LAN” capability introduced in IPMI v2.0.
     */
    std::vector<uint8_t> payload;
};

namespace LAN
{

constexpr uint8_t requesterBMCAddress = 0x20;
constexpr uint8_t responderBMCAddress = 0x81;

namespace header
{

/**
 * @struct IPMI LAN Message Request Header
 */
struct Request
{
    uint8_t rsaddr;
    uint8_t netfn;
    uint8_t cs;
    uint8_t rqaddr;
    uint8_t rqseq;
    uint8_t cmd;
} __attribute__((packed));

/**
 * @struct IPMI LAN Message Response Header
 */
struct Response
{
    uint8_t rqaddr;
    uint8_t netfn;
    uint8_t cs;
    uint8_t rsaddr;
    uint8_t rqseq;
    uint8_t cmd;
} __attribute__((packed));

} // namespace header

namespace trailer
{

/**
 * @struct IPMI LAN Message Trailer
 */
struct Request
{
    uint8_t checksum;
} __attribute__((packed));

using Response = Request;

} // namespace trailer

} // namespace LAN

} // namespace message
