#include "sol_context.hpp"

#include "main.hpp"
#include "message_handler.hpp"
#include "sd_event_loop.hpp"
#include "sessions_manager.hpp"
#include "sol_manager.hpp"

#include <errno.h>

#include <phosphor-logging/lg2.hpp>

namespace sol
{
using namespace phosphor::logging;

Context::Context(std::shared_ptr<boost::asio::io_context> io,
                 uint8_t maxRetryCount, uint8_t sendThreshold, uint8_t instance,
                 session::SessionID sessionID) :
    accumulateTimer(*io), retryTimer(*io), maxRetryCount(maxRetryCount),
    retryCounter(maxRetryCount), sendThreshold(sendThreshold),
    payloadInstance(instance), sessionID(sessionID)
{
    session = session::Manager::get().getSession(sessionID);
}

std::shared_ptr<Context> Context::makeContext(
    std::shared_ptr<boost::asio::io_context> io, uint8_t maxRetryCount,
    uint8_t sendThreshold, uint8_t instance, session::SessionID sessionID)
{
    auto ctx = std::make_shared<Context>(io, maxRetryCount, sendThreshold,
                                         instance, sessionID);
    ctx->enableAccumulateTimer(true);
    return ctx;
}

void Context::enableAccumulateTimer(bool enable)
{
    // fetch the timeout from the SOL manager
    std::chrono::microseconds interval = sol::Manager::get().accumulateInterval;

    if (enable)
    {
        auto bufferSize = sol::Manager::get().dataBuffer.size();
        if (bufferSize > sendThreshold)
        {
            try
            {
                int rc = sendOutboundPayload();
                if (rc == 0)
                {
                    return;
                }
            }
            catch (const std::exception& e)
            {
                lg2::error(
                    "Failed to call the sendOutboundPayload method: {ERROR}",
                    "ERROR", e);
                return;
            }
        }
        accumulateTimer.expires_after(interval);
        std::weak_ptr<Context> weakRef = weak_from_this();
        accumulateTimer.async_wait(
            [weakRef](const boost::system::error_code& ec) {
                std::shared_ptr<Context> self = weakRef.lock();
                if (!ec && self)
                {
                    self->charAccTimerHandler();
                }
            });
    }
    else
    {
        accumulateTimer.cancel();
    }
}

void Context::enableRetryTimer(bool enable)
{
    if (enable)
    {
        // fetch the timeout from the SOL manager
        std::chrono::microseconds interval = sol::Manager::get().retryInterval;
        retryTimer.expires_after(interval);
        std::weak_ptr<Context> weakRef = weak_from_this();
        retryTimer.async_wait([weakRef](const boost::system::error_code& ec) {
            std::shared_ptr<Context> self = weakRef.lock();
            if (!ec && self)
            {
                self->retryTimerHandler();
            }
        });
    }
    else
    {
        retryTimer.cancel();
    }
}

void Context::processInboundPayload(uint8_t seqNum, uint8_t ackSeqNum,
                                    uint8_t count, bool status, bool isBreak,
                                    const std::vector<uint8_t>& input)
{
    uint8_t respAckSeqNum = 0;
    uint8_t acceptedCount = 0;
    auto ack = false;

    /*
     * Check if the Inbound sequence number is same as the expected one.
     * If the Packet Sequence Number is 0, it is an ACK-Only packet. Multiple
     * outstanding sequence numbers are not supported in this version of the SOL
     * specification. Retried packets use the same sequence number as the first
     * packet.
     */
    if (seqNum && (seqNum != seqNums.get(true)))
    {
        lg2::info("Out of sequence SOL packet - packet is dropped");
        return;
    }

    /*
     * Check if the expected ACK/NACK sequence number is same as the
     * ACK/NACK sequence number in the packet. If packet ACK/NACK sequence
     * number is 0, then it is an informational packet. No request packet being
     * ACK'd or NACK'd.
     */
    if (ackSeqNum && (ackSeqNum != seqNums.get(false)))
    {
        lg2::info("Out of sequence ack number - SOL packet is dropped");
        return;
    }

    /*
     * Retry the SOL payload packet in the following conditions:
     *
     * a) NACK in Operation/Status
     * b) Accepted Character Count does not match with the sent out SOL payload
     * c) Non-zero Packet ACK/NACK Sequence Number
     */
    if (status || ((count != expectedCharCount) && ackSeqNum))
    {
        resendPayload(noClear);
        enableRetryTimer(false);
        enableRetryTimer(true);
        return;
    }
    /*
     * Clear the sent data once the acknowledgment sequence number matches
     * and the expected character count matches.
     */
    else if ((count == expectedCharCount) && ackSeqNum)
    {
        // Clear the Host Console Buffer
        sol::Manager::get().dataBuffer.erase(count);

        // Once it is acknowledged stop the retry interval timer
        enableRetryTimer(false);

        retryCounter = maxRetryCount;
        expectedCharCount = 0;
        payloadCache.clear();
    }

    if (isBreak && seqNum)
    {
        lg2::info("Writing break to console socket descriptor");
        constexpr uint8_t sysrqValue = 72; // use this to notify sol server
        const std::vector<uint8_t> test{sysrqValue};
        auto ret = sol::Manager::get().writeConsoleSocket(test, isBreak);
        if (ret)
        {
            lg2::error("Writing to console socket descriptor failed: {ERROR}",
                       "ERROR", strerror(errno));
        }
    }

    isBreak = false;
    // Write character data to the Host Console
    if (!input.empty() && seqNum)
    {
        auto rc = sol::Manager::get().writeConsoleSocket(input, isBreak);
        if (rc)
        {
            lg2::error("Writing to console socket descriptor failed: {ERROR}",
                       "ERROR", strerror(errno));
            ack = true;
        }
        else
        {
            respAckSeqNum = seqNum;
            ack = false;
            acceptedCount = input.size();
        }
    }
    /*
     * SOL payload with no character data and valid sequence number can be used
     * as method to keep the SOL session active.
     */
    else if (input.empty() && seqNum)
    {
        respAckSeqNum = seqNum;
    }

    if (seqNum != 0)
    {
        seqNums.incInboundSeqNum();
        prepareResponse(respAckSeqNum, acceptedCount, ack);
    }
    else
    {
        enableAccumulateTimer(true);
    }
}

void Context::prepareResponse(uint8_t ackSeqNum, uint8_t count, bool ack)
{
    auto bufferSize = sol::Manager::get().dataBuffer.size();

    /* Sent a ACK only response */
    if (payloadCache.size() != 0 || (bufferSize < sendThreshold))
    {
        enableAccumulateTimer(true);

        std::vector<uint8_t> outPayload(sizeof(Payload));
        auto response = reinterpret_cast<Payload*>(outPayload.data());
        response->packetSeqNum = 0;
        response->packetAckSeqNum = ackSeqNum;
        response->acceptedCharCount = count;
        response->outOperation.ack = ack;
        sendPayload(outPayload);
        return;
    }

    auto readSize = std::min(bufferSize, MAX_PAYLOAD_SIZE);
    payloadCache.resize(sizeof(Payload) + readSize);
    auto response = reinterpret_cast<Payload*>(payloadCache.data());
    response->packetAckSeqNum = ackSeqNum;
    response->acceptedCharCount = count;
    response->outOperation.ack = ack;
    response->packetSeqNum = seqNums.incOutboundSeqNum();

    auto handle = sol::Manager::get().dataBuffer.read();
    std::copy_n(handle, readSize, payloadCache.data() + sizeof(Payload));
    expectedCharCount = readSize;

    enableRetryTimer(true);
    enableAccumulateTimer(false);

    sendPayload(payloadCache);
}

int Context::sendOutboundPayload()
{
    if (payloadCache.size() != 0)
    {
        return -1;
    }

    auto bufferSize = sol::Manager::get().dataBuffer.size();
    auto readSize = std::min(bufferSize, MAX_PAYLOAD_SIZE);

    payloadCache.resize(sizeof(Payload) + readSize);
    auto response = reinterpret_cast<Payload*>(payloadCache.data());
    response->packetAckSeqNum = 0;
    response->acceptedCharCount = 0;
    response->outOperation.ack = false;
    response->packetSeqNum = seqNums.incOutboundSeqNum();

    auto handle = sol::Manager::get().dataBuffer.read();
    std::copy_n(handle, readSize, payloadCache.data() + sizeof(Payload));
    expectedCharCount = readSize;

    enableRetryTimer(true);
    enableAccumulateTimer(false);

    sendPayload(payloadCache);

    return 0;
}

void Context::resendPayload(bool clear)
{
    sendPayload(payloadCache);

    if (clear)
    {
        payloadCache.clear();
        expectedCharCount = 0;
        sol::Manager::get().dataBuffer.erase(expectedCharCount);
    }
}

void Context::sendPayload(const std::vector<uint8_t>& out) const
{
    message::Handler msgHandler(session->channelPtr, sessionID);

    msgHandler.sendSOLPayload(out);
}

void Context::charAccTimerHandler()
{
    auto bufferSize = sol::Manager::get().dataBuffer.size();

    try
    {
        if (bufferSize > 0)
        {
            int rc = sendOutboundPayload();
            if (rc == 0)
            {
                return;
            }
        }
        enableAccumulateTimer(true);
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to call the sendOutboundPayload method: {ERROR}",
                   "ERROR", e);
    }
}

void Context::retryTimerHandler()
{
    try
    {
        if (retryCounter)
        {
            --retryCounter;
            enableRetryTimer(true);
            resendPayload(sol::Context::noClear);
        }
        else
        {
            retryCounter = maxRetryCount;
            resendPayload(sol::Context::clear);
            enableRetryTimer(false);
            enableAccumulateTimer(true);
        }
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to retry timer: {ERROR}", "ERROR", e);
    }
}
} // namespace sol
