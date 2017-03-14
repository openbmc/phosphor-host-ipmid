#include <phosphor-logging/log.hpp>
#include "main.hpp"
#include "sd_event_loop.hpp"
#include "sol_context.hpp"
#include "sol_manager.hpp"

namespace sol
{

using namespace phosphor::logging;

void Context::processInboundPayload(uint8_t seqNum,
                                    uint8_t ackSeqNum,
                                    uint8_t count,
                                    bool status,
                                    const Buffer& input)
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
    if(seqNum && (seqNum != seqNums.get(true)))
    {
        log<level::INFO>("Out of sequence SOL packet - packet is dropped");
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
        log<level::INFO>("Out of sequence ack number - SOL packet is dropped");
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
        std::get<eventloop::EventLoop&>(singletonPool).switchTimer
                (payloadInstance, eventloop::Timers::RETRY, false);
        std::get<eventloop::EventLoop&>(singletonPool).switchTimer
                (payloadInstance, eventloop::Timers::RETRY, true);
        return;
    }
    /*
     * Clear the sent data once the acknowledgment sequence number matches
     * and the expected character count matches.
     */
    else if ((count == expectedCharCount) && ackSeqNum)
    {
        // Clear the Host Console Buffer
        std::get<sol::Manager&>(singletonPool).dataBuffer.erase(count);

        // Once it is acknowledged stop the retry interval timer
        std::get<eventloop::EventLoop&>(singletonPool).switchTimer(
                payloadInstance, eventloop::Timers::RETRY, false);

        retryCounter = maxRetryCount;
        expectedCharCount = 0;
        payloadCache.clear();
    }

    // Write character data to the Host Console
    if (!input.empty() && seqNum)
    {
        auto rc = std::get<sol::Manager&>(singletonPool).writeConsoleSocket(
                input);
        if (rc)
        {
            log<level::ERR>("Writing to console socket descriptor failed");
            ack = true;
        }
        else
        {
            respAckSeqNum = seqNum;
            ack = false;
            acceptedCount = input.size();
        }
    }

    if (seqNum != 0)
    {
        seqNums.incInboundSeqNum();
        prepareResponse(respAckSeqNum, acceptedCount, ack);
    }
    else
    {
        std::get<eventloop::EventLoop&>(singletonPool).switchTimer
                (payloadInstance, eventloop::Timers::ACCUMULATE, true);
    }
}

void Context::prepareResponse(uint8_t ackSeqNum, uint8_t count, bool ack)
{
    auto bufferSize = std::get<sol::Manager&>(singletonPool).dataBuffer.
                            size();

    /* Sent a ACK only response */
    if (payloadCache.size() != 0 || (bufferSize < sendThreshold))
    {
        std::get<eventloop::EventLoop&>(singletonPool).switchTimer
                (payloadInstance, eventloop::Timers::ACCUMULATE, true);

        Buffer outPayload(sizeof(Payload));
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


    auto handle = std::get<sol::Manager&>(singletonPool).dataBuffer.read();
    std::copy_n(handle, readSize, payloadCache.data() + sizeof(Payload));
    expectedCharCount = readSize;

    std::get<eventloop::EventLoop&>(singletonPool).switchTimer(
            payloadInstance, eventloop::Timers::RETRY, true);
    std::get<eventloop::EventLoop&>(singletonPool).switchTimer
            (payloadInstance, eventloop::Timers::ACCUMULATE, false);

    sendPayload(payloadCache);
}

void Context::resendPayload(bool clear)
{

}

void Context::sendPayload(const Buffer& out) const
{

}

} // namespace sol
