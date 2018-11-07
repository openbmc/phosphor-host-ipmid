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
        auto msgHandler = std::make_shared<message::Handler>(channelPtr, io);

        msgHandler->processIncoming();
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

} // namespace eventloop
