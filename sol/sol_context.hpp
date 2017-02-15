#pragma once

#include "console_buffer.hpp"
#include "session.hpp"

namespace sol
{

namespace internal
{

/** @struct SequenceNumbers
 *
 *  SOL sequence numbers. At the session level, SOL Payloads share the session
 *  sequence numbers for authenticated and unauthenticated packets with other
 *  packets under the IPMI session. At the payload level, SOL packets include
 *  their own message sequence numbers that are used for tracking missing and
 *  retried SOL messages. The sequence numbers must be non-zero. Retried
 *  packets use the same sequence number as the first packet.
 */
struct SequenceNumbers
{
    static constexpr uint8_t MAX_SOL_SEQUENCE_NUMBER = 0x10;

    /** @brief Get the SOL sequence number.
     *
     *  @param[in] inbound - true for inbound sequence number and false for
     *                       outbound sequence number
     *
     *  @return sequence number
     */
    auto get(bool inbound = true) const
    {
        return inbound ? in : out;
    }

    /** @brief Increment the inbound SOL sequence number. */
    void incInboundSeqNum()
    {
        if ((++in) == MAX_SOL_SEQUENCE_NUMBER)
        {
            in = 1;
        }
    }

    /** @brief Increment the outbound SOL sequence number.
     *
     *  @return outbound sequence number to populate the SOL payload.
     */
    auto incOutboundSeqNum()
    {
        if ((++out) == MAX_SOL_SEQUENCE_NUMBER)
        {
            out = 1;
        }

        return out;
    }

    private:
        uint8_t in = 1;     //!< Inbound sequence number.
        uint8_t out = 0;    //!< Outbound sequence number, since the first
                            //!< operation is increment, it is initialised to 0
};

} // namespace internal

/** @class Context
 *
 *  Context keeps the state of the SOL session. The information needed to
 *  maintain the state of the SOL is part of this class. This class provides
 *  interfaces to handle incoming SOL payload, send response and send outbound
 *  SOL payload.
 */
class Context
{
    public:
        Context() = default;
        ~Context() = default;
        Context(const Context&) = delete;
        Context& operator=(const Context&) = delete;
        Context(Context&&) = default;
        Context& operator=(Context&&) = default;

        /** @brief Context Constructor.
         *
         *  This is issued by the SOL Manager when a SOL payload instance is
         *  started for the activate payload command.
         *
         *  @param[in] maxRetryCount  - Retry count max value.
         *  @param[in] sendThreshold - Character send threshold.
         *  @param[in] instance - SOL payload instance.
         *  @param[in] sessionID - BMC session ID.
         */
        Context(uint8_t maxRetryCount,
                uint8_t sendThreshold,
                uint8_t instance,
                session::SessionID sessionID):
            maxRetryCount(maxRetryCount),
            retryCounter(maxRetryCount),
            sendThreshold(sendThreshold),
            payloadInstance(instance),
            sessionID(sessionID) {}

        static constexpr auto clear = true;
        static constexpr auto noClear = false;

        /** @brief Retry count max value. */
        const uint8_t maxRetryCount = 0;

        /** @brief Retry counter. */
        uint8_t retryCounter = 0;

        /** @brief Character send threshold. */
        const uint8_t sendThreshold = 0;

        /** @brief SOL payload instance. */
        const uint8_t payloadInstance = 0;

        /** @brief Session ID. */
        const session::SessionID sessionID = 0;

        /** @brief Process the Inbound SOL payload.
         *
         *  The SOL payload from the remote console is processed and the
         *  acknowledgment handling is done.
         *
         *  @param[in] seqNum - Packet sequence number.
         *  @param[in] ackSeqNum - Packet ACK/NACK sequence number.
         *  @param[in] count - Accepted character count.
         *  @param[in] operation - ACK is false, NACK is true
         *  @param[in] input - Incoming SOL character data.
         */
        void processInboundPayload(uint8_t seqNum,
                                   uint8_t ackSeqNum,
                                   uint8_t count,
                                   bool status,
                                   const Buffer& input);

        /** @brief Send the outbound SOL payload.
         *
         *  @return zero on success and negative value if condition for sending
         *          the payload fails.
         */
        int sendOutboundPayload();

        /** @brief Resend the SOL payload.
         *
         *  @param[in] clear - if true then send the payload and clear the
         *                     cached payload, if false only send the payload.
         */
        void resendPayload(bool clear);

    private:
        /** @brief Expected character count.
         *
         *  Expected Sequence number and expected character count is set before
         *  sending the SOL payload. The check is done against these values when
         *  an incoming SOL payload is received.
         */
        size_t expectedCharCount = 0;

        /** @brief Inbound and Outbound sequence numbers. */
        internal::SequenceNumbers seqNums;

        /** @brief Copy of the last sent SOL payload.
         *
         *  A copy of the SOL payload is kept here, so that when a retry needs
         *  to be attempted the payload is sent again.
         */
        Buffer payloadCache;

        /**
         * @brief Send Response for Incoming SOL payload.
         *
         * @param[in] ackSeqNum - Packet ACK/NACK Sequence Number.
         * @param[in] count - Accepted Character Count.
         * @param[in] ack - Set ACK/NACK in the Operation.
         */
        void prepareResponse(uint8_t ackSeqNum, uint8_t count, bool ack);

        /** @brief Send the outgoing SOL payload.
         *
         *  @param[in] out - buffer containing the SOL payload.
         */
        void sendPayload(const Buffer& out) const;
};

} // namespace sol
