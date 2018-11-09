#include "sd_event_loop.hpp"

#include "main.hpp"
#include "message_handler.hpp"

#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <systemd/sd-daemon.h>

#include <boost/asio/io_context.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/sd_event.hpp>

namespace eventloop
{
using namespace phosphor::logging;

void EventLoop::handleRmcpPacket()
{
    try
    {
        auto channelPtr = std::make_shared<udpsocket::Channel>(udpSocket);

        // Initialize the Message Handler with the socket channel
        auto msgHandler = std::make_shared<message::Handler>(channelPtr);

        // Read the incoming IPMI packet
        std::shared_ptr<message::Message> inMessage(msgHandler->receive());
        if (inMessage == nullptr)
        {
            return;
        }

        // Execute the Command
        std::shared_ptr<message::Message> outMessage =
            msgHandler->executeCommand(inMessage);
        if (outMessage == nullptr)
        {
            return;
        }
        // Send the response IPMI Message
        msgHandler->send(outMessage);
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("Executing the IPMI message failed",
                        entry("EXCEPTION=%s", e.what()));
    }
}

void EventLoop::startRmcpReceive()
{
    udpSocket->async_wait(boost::asio::socket_base::wait_read,
                          [this](const boost::system::error_code& ec) {
                              if (!ec)
                              {
                                  io->post([this]() { startRmcpReceive(); });
                                  handleRmcpPacket();
                              }
                          });
}

static int consoleInputHandler(sd_event_source* es, int fd, uint32_t revents,
                               void* userdata)
{
    try
    {
        int readSize = 0;

        if (ioctl(fd, FIONREAD, &readSize) < 0)
        {
            log<level::ERR>("ioctl failed for FIONREAD:",
                            entry("ERRNO=%d", errno));
            return 0;
        }

        std::vector<uint8_t> buffer(readSize);
        auto bufferSize = buffer.size();
        ssize_t readDataLen = 0;

        readDataLen = read(fd, buffer.data(), bufferSize);

        // Update the Console buffer with data read from the socket
        if (readDataLen > 0)
        {
            buffer.resize(readDataLen);
            std::get<sol::Manager&>(singletonPool).dataBuffer.write(buffer);
        }
        else if (readDataLen == 0)
        {
            log<level::ERR>("Connection Closed for host console socket");
        }
        else if (readDataLen < 0) // Error
        {
            log<level::ERR>("Reading from host console socket failed:",
                            entry("ERRNO=%d", errno));
        }
    }
    catch (std::exception& e)
    {
        log<level::ERR>(e.what());
    }

    return 0;
}

static int charAccTimerHandler(sd_event_source* s, uint64_t usec,
                               void* userdata)
{
    auto bufferSize = std::get<sol::Manager&>(singletonPool).dataBuffer.size();

    try
    {
        // The instance is hardcoded to 1, in the case of supporting multiple
        // payload instances we would need to populate it from userdata
        uint8_t instance = 1;

        if (bufferSize > 0)
        {
            auto& context =
                std::get<sol::Manager&>(singletonPool).getContext(instance);

            int rc = context.sendOutboundPayload();

            if (rc == 0)
            {
                return 0;
            }
        }

        std::get<eventloop::EventLoop&>(singletonPool)
            .switchTimer(instance, Timers::ACCUMULATE, true);
    }
    catch (std::exception& e)
    {
        log<level::ERR>(e.what());
    }

    return 0;
}

static int retryTimerHandler(sd_event_source* s, uint64_t usec, void* userdata)
{
    try
    {
        // The instance is hardcoded to 1, in the case of supporting multiple
        // payload instances we would need to populate it from userdata
        uint8_t instance = 1;

        auto& context =
            std::get<sol::Manager&>(singletonPool).getContext(instance);

        if (context.retryCounter)
        {
            --context.retryCounter;
            std::get<eventloop::EventLoop&>(singletonPool)
                .switchTimer(instance, Timers::RETRY, true);
            context.resendPayload(sol::Context::noClear);
        }
        else
        {
            context.retryCounter = context.maxRetryCount;
            context.resendPayload(sol::Context::clear);
            std::get<eventloop::EventLoop&>(singletonPool)
                .switchTimer(instance, Timers::RETRY, false);
            std::get<eventloop::EventLoop&>(singletonPool)
                .switchTimer(instance, Timers::ACCUMULATE, true);
        }
    }
    catch (std::exception& e)
    {
        log<level::ERR>(e.what());
    }

    return 0;
}

int EventLoop::startEventLoop()
{
    sdbusplus::asio::sd_event_wrapper sdEvents(*io);
    event = sdEvents.get();

    // set up boost::asio signal handling
    boost::asio::signal_set signals(*io, SIGINT, SIGTERM);
    signals.async_wait(
        [this](const boost::system::error_code& error, int signalNumber) {
            udpSocket->cancel();
            udpSocket->close();
            io->stop();
        });

    // Create our own socket if SysD did not supply one.
    int listensFdCount = sd_listen_fds(0);
    if (listensFdCount == 1)
    {
        if (sd_is_socket(SD_LISTEN_FDS_START, AF_UNSPEC, SOCK_DGRAM, -1))
        {
            udpSocket = std::make_shared<boost::asio::ip::udp::socket>(
                *io, boost::asio::ip::udp::v6(), SD_LISTEN_FDS_START);
        }
    }
    else if (listensFdCount > 1)
    {
        log<level::ERR>("Too many file descriptors received");
        return EXIT_FAILURE;
    }
    if (!udpSocket)
    {
        udpSocket = std::make_shared<boost::asio::ip::udp::socket>(
            *io, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v6(),
                                                IPMI_STD_PORT));
        if (!udpSocket)
        {
            log<level::ERR>("Failed to start listening on RMCP socket");
            return EXIT_FAILURE;
        }
    }
    startRmcpReceive();

    io->run();

    return EXIT_SUCCESS;
}

void EventLoop::startHostConsole(const sol::CustomFD& fd)
{
    int rc = 0;

    if ((fd() == -1) || hostConsole.get())
    {
        throw std::runtime_error("Console descriptor already added");
    }

    sd_event_source* source = nullptr;

    // Add the fd to the event loop for EPOLLIN
    rc = sd_event_add_io(event, &source, fd(), EPOLLIN, consoleInputHandler,
                         nullptr);
    if (rc < 0)
    {
        throw std::runtime_error("Failed to add socket descriptor");
    }

    hostConsole.reset(source);
    source = nullptr;
}

void EventLoop::stopHostConsole()
{
    if (hostConsole.get())
    {
        // Disable the host console payload
        int rc = sd_event_source_set_enabled(hostConsole.get(), SD_EVENT_OFF);
        if (rc < 0)
        {
            log<level::ERR>("Failed to disable the host console socket",
                            entry("RC=%d", rc));
        }

        hostConsole.reset();
    }
}

void EventLoop::startSOLPayloadInstance(uint8_t payloadInst,
                                        IntervalType accumulateInterval,
                                        IntervalType retryInterval)
{
    auto instance = payloadInst;
    sd_event_source* accTimerSource = nullptr;
    sd_event_source* retryTimerSource = nullptr;
    int rc = 0;
    uint64_t currentTime = 0;

    rc = sd_event_now(event, CLOCK_MONOTONIC, &currentTime);
    if (rc < 0)
    {
        log<level::ERR>("Failed to get the current timestamp",
                        entry("RC=%d", rc));
        throw std::runtime_error("Failed to get current timestamp");
    }

    // Create character accumulate timer
    rc = sd_event_add_time(event, &accTimerSource, CLOCK_MONOTONIC,
                           currentTime + accumulateInterval.count(), 0,
                           charAccTimerHandler, static_cast<void*>(&instance));
    if (rc < 0)
    {
        log<level::ERR>("Failed to setup the accumulate timer",
                        entry("RC=%d", rc));
        throw std::runtime_error("Failed to setup accumulate timer");
    }

    // Create retry interval timer and add to the event loop
    rc = sd_event_add_time(event, &retryTimerSource, CLOCK_MONOTONIC,
                           currentTime + retryInterval.count(), 0,
                           retryTimerHandler, static_cast<void*>(&instance));
    if (rc < 0)
    {
        log<level::ERR>("Failed to setup the retry timer", entry("RC=%d", rc));
        throw std::runtime_error("Failed to setup retry timer");
    }

    // Enable the Character Accumulate Timer
    rc = sd_event_source_set_enabled(accTimerSource, SD_EVENT_ONESHOT);
    if (rc < 0)
    {
        log<level::ERR>("Failed to enable the accumulate timer",
                        entry("RC=%d", rc));
        throw std::runtime_error("Failed to enable accumulate timer");
    }

    // Disable the Retry Interval Timer
    rc = sd_event_source_set_enabled(retryTimerSource, SD_EVENT_OFF);
    if (rc < 0)
    {
        log<level::ERR>("Failed to disable the retry timer",
                        entry("RC=%d", rc));
        throw std::runtime_error("Failed to disable retry timer");
    }

    EventSource accEventSource(accTimerSource);
    EventSource retryEventSource(retryTimerSource);
    accTimerSource = nullptr;
    retryTimerSource = nullptr;

    TimerMap timer;
    timer.emplace(Timers::ACCUMULATE, std::make_tuple(std::move(accEventSource),
                                                      accumulateInterval));
    timer.emplace(Timers::RETRY,
                  std::make_tuple(std::move(retryEventSource), retryInterval));
    payloadInfo.emplace(instance, std::move(timer));
}

void EventLoop::stopSOLPayloadInstance(uint8_t payloadInst)
{
    auto iter = payloadInfo.find(payloadInst);
    if (iter == payloadInfo.end())
    {
        log<level::ERR>("SOL Payload instance not found",
                        entry("PAYLOADINST=%d", payloadInst));
        throw std::runtime_error("SOL payload instance not found");
    }

    int rc = 0;

    /* Destroy the character accumulate timer event source */
    rc = sd_event_source_set_enabled(
        (std::get<0>(iter->second.at(Timers::ACCUMULATE))).get(), SD_EVENT_OFF);
    if (rc < 0)
    {
        log<level::ERR>("Failed to disable the character accumulate timer",
                        entry("RC=%d", rc));
        payloadInfo.erase(payloadInst);
        throw std::runtime_error("Failed to disable accumulate timer");
    }

    /* Destroy the retry interval timer event source */
    rc = sd_event_source_set_enabled(
        (std::get<0>(iter->second.at(Timers::RETRY))).get(), SD_EVENT_OFF);
    if (rc < 0)
    {
        log<level::ERR>("Failed to disable the retry timer",
                        entry("RC=%d", rc));
        payloadInfo.erase(payloadInst);
        throw std::runtime_error("Failed to disable retry timer");
    }

    payloadInfo.erase(payloadInst);
}

void EventLoop::switchTimer(uint8_t payloadInst, Timers type, bool status)
{
    auto iter = payloadInfo.find(payloadInst);
    if (iter == payloadInfo.end())
    {
        log<level::ERR>("SOL Payload instance not found",
                        entry("PAYLOADINST=%d", payloadInst));
        throw std::runtime_error("SOL Payload instance not found");
    }

    int rc = 0;
    auto source = (std::get<0>(iter->second.at(type))).get();
    auto interval = std::get<1>(iter->second.at(type));

    // Turn OFF the timer
    if (!status)
    {
        rc = sd_event_source_set_enabled(source, SD_EVENT_OFF);
        if (rc < 0)
        {
            log<level::ERR>("Failed to disable the timer", entry("RC=%d", rc));
            throw std::runtime_error("Failed to disable timer");
        }
        return;
    }

    // Turn ON the timer
    uint64_t currentTime = 0;
    rc = sd_event_now(event, CLOCK_MONOTONIC, &currentTime);
    if (rc < 0)
    {
        log<level::ERR>("Failed to get the current timestamp",
                        entry("RC=%d", rc));
        throw std::runtime_error("Failed to get current timestamp");
    }

    rc = sd_event_source_set_time(source, currentTime + interval.count());
    if (rc < 0)
    {
        log<level::ERR>("sd_event_source_set_time function failed",
                        entry("RC=%d", rc));
        throw std::runtime_error("sd_event_source_set_time function failed");
    }

    rc = sd_event_source_set_enabled(source, SD_EVENT_ONESHOT);
    if (rc < 0)
    {
        log<level::ERR>("Failed to enable the timer", entry("RC=%d", rc));
        throw std::runtime_error("Failed to enable timer");
    }
}

} // namespace eventloop
