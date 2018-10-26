#pragma once

#include "message.hpp"
#include "message_parsers.hpp"
#include "session.hpp"
#include "sol/console_buffer.hpp"

#include <memory>

namespace message
{

class Handler
{
  public:
    explicit Handler(
        std::shared_ptr<udpsocket::Channel> channel,
        uint32_t sessionID = message::Message::MESSAGE_INVALID_SESSION_ID) :
        sessionID(sessionID),
        channel(channel)
    {
    }

    Handler() = delete;
    ~Handler() = default;
    Handler(const Handler&) = delete;
    Handler& operator=(const Handler&) = delete;
    Handler(Handler&&) = delete;
    Handler& operator=(Handler&&) = delete;

    /**
     * @brief Receive the IPMI packet
     *
     * Read the data on the socket, get the parser based on the Session
     * header type and flatten the payload and generate the IPMI message
     *
     * @return IPMI Message on success and nullptr on failure
     *
     */
    std::shared_ptr<Message> receive();

    /**
     * @brief Process the incoming IPMI message
     *
     * The incoming message payload is handled and the command handler for
     * the Network function and Command is executed and the response message
     * is returned
     *
     * @param[in] inMessage - Incoming Message
     *
     * @return Outgoing message on success and nullptr on failure
     */
    std::shared_ptr<Message> executeCommand(std::shared_ptr<Message> inMessage);

    /** @brief Send the outgoing message
     *
     *  The payload in the outgoing message is flattened and sent out on the
     *  socket
     *
     *  @param[in] outMessage - Outgoing Message
     */
    void send(std::shared_ptr<Message> outMessage);

    /** @brief Set socket channel in session object */
    void setChannelInSession() const;

    /** @brief Send the SOL payload
     *
     *  The SOL payload is flattened and sent out on the socket
     *
     *  @param[in] input - SOL Payload
     */
    void sendSOLPayload(const std::vector<uint8_t>& input);

    /** @brief Send the unsolicited IPMI payload to the remote console.
     *
     *  This is used by commands like SOL activating, in which case the BMC
     *  has to notify the remote console that a SOL payload is activating
     *  on another channel.
     *
     *  @param[in] netfn - Net function.
     *  @param[in] cmd - Command.
     *  @param[in] input - Command request data.
     */
    void sendUnsolicitedIPMIPayload(uint8_t netfn, uint8_t cmd,
                                    const std::vector<uint8_t>& input);

    // BMC Session ID for the Channel
    session::SessionID sessionID;

  private:
    /** @brief Socket channel for communicating with the remote client.*/
    std::shared_ptr<udpsocket::Channel> channel;

    parser::SessionHeader sessionHeader = parser::SessionHeader::IPMI20;
};

} // namespace message
