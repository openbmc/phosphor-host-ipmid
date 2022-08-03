#pragma once

#include "message.hpp"
#include "message_parsers.hpp"
#include "session.hpp"
#include "sessions_manager.hpp"
#include "sol/console_buffer.hpp"

#include <memory>

namespace message
{

class Handler : public std::enable_shared_from_this<Handler>
{
  public:
    /**
     * @brief Create a Handler intended for a full transaction
     *        that may or may not use asynchronous responses
     */
    Handler(std::shared_ptr<udpsocket::Channel> channel,
            std::shared_ptr<boost::asio::io_context> io,
            uint32_t sessionID = message::Message::MESSAGE_INVALID_SESSION_ID) :
        sessionID(sessionID),
        channel(channel), io(io)
    {
        if (sessionID != message::Message::MESSAGE_INVALID_SESSION_ID)
        {
            session = session::Manager::get().getSession(sessionID);
        }
    }

    /**
     * @brief Create a Handler intended for a send only (SOL)
     */
    Handler(std::shared_ptr<udpsocket::Channel> channel,
            uint32_t sessionID = message::Message::MESSAGE_INVALID_SESSION_ID) :
        sessionID(sessionID),
        channel(channel), io(nullptr)
    {
        if (sessionID != message::Message::MESSAGE_INVALID_SESSION_ID)
        {
            session = session::Manager::get().getSession(sessionID);
        }
    }

    ~Handler();
    Handler() = delete;
    Handler(const Handler&) = delete;
    Handler& operator=(const Handler&) = delete;
    Handler(Handler&&) = delete;
    Handler& operator=(Handler&&) = delete;

    /**
     * @brief Process the incoming IPMI message
     *
     * The incoming payload is read from the channel. If a message is read, it
     * is passed onto executeCommand, which may or may not execute the command
     * asynchrounously. If the command is executed asynchrounously, a shared_ptr
     * of self via shared_from_this will keep this object alive until the
     * response is ready. Then on the destructor, the response will be sent.
     */
    void processIncoming();

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

    /** @brief response to send back */
    std::optional<std::vector<uint8_t>> outPayload;

  private:
    /**
     * @brief Receive the IPMI packet
     *
     * Read the data on the socket, get the parser based on the Session
     * header type and flatten the payload and generate the IPMI message
     */
    bool receive();

    /**
     * @brief Get Session data from the IPMI packet
     *
     */
    void updSessionData(std::shared_ptr<Message>& inMessage);

    /**
     * @brief Process the incoming IPMI message
     *
     * The incoming message payload is handled and the command handler for
     * the Network function and Command is executed and the response message
     * is returned
     */
    void executeCommand();

    /** @brief Send the outgoing message
     *
     *  The payload in the outgoing message is flattened and sent out on the
     *  socket
     *
     *  @param[in] outMessage - Outgoing Message
     */
    void send(std::shared_ptr<Message> outMessage);

#ifdef RMCP_PING
    /** @brief Send the outgoing ASF message
     *
     *  The outgoing ASF message contains only ASF message header
     *  which is flattened and sent out on the socket
     */
    void sendASF();
#endif // RMCP_PING

    /** @brief Write the packet to the socket
     *
     *  @param[in] packet - Outgoing packet
     */
    void writeData(const std::vector<uint8_t>& packet);

    /** @brief Socket channel for communicating with the remote client.*/
    std::shared_ptr<udpsocket::Channel> channel;

    /** @brief asio io context to run asynchrounously */
    std::shared_ptr<boost::asio::io_context> io;

    parser::SessionHeader sessionHeader = parser::SessionHeader::IPMI20;

    std::shared_ptr<message::Message> inMessage{};

    /** @brief The IPMI session of the handler */
    std::shared_ptr<session::Session> session{};
};

} // namespace message
