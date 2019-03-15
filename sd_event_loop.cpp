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

int EventLoop::setupSocket(std::shared_ptr<sdbusplus::asio::connection>& bus,
                           std::string iface, uint16_t reqPort)
{
    static constexpr const char* unboundIface = "rmcpp";
    if (iface == "")
    {
        iface = unboundIface;
    }
    // Create our own socket if SysD did not supply one.
    int listensFdCount = sd_listen_fds(0);
    if (listensFdCount > 1)
    {
        log<level::ERR>("Too many file descriptors received");
        return EXIT_FAILURE;
    }
    if (listensFdCount == 1)
    {
        int openFd = SD_LISTEN_FDS_START;
        if (!sd_is_socket(openFd, AF_UNSPEC, SOCK_DGRAM, -1))
        {
            log<level::ERR>("Failed to set up systemd-passed socket");
            return EXIT_FAILURE;
        }
        udpSocket = std::make_shared<boost::asio::ip::udp::socket>(
            *io, boost::asio::ip::udp::v6(), openFd);
    }
    else
    {
        // asio does not natively offer a way to bind to an interface
        // so it must be done in steps
        boost::asio::ip::udp::endpoint ep(boost::asio::ip::udp::v6(), reqPort);
        udpSocket = std::make_shared<boost::asio::ip::udp::socket>(*io);
        udpSocket->open(ep.protocol());
        // bind
        udpSocket->set_option(
            boost::asio::ip::udp::socket::reuse_address(true));
        udpSocket->bind(ep);
    }
    // SO_BINDTODEVICE
    char nameout[IFNAMSIZ];
    unsigned int lenout = sizeof(nameout);
    if ((::getsockopt(udpSocket->native_handle(), SOL_SOCKET, SO_BINDTODEVICE,
                      nameout, &lenout) == -1))
    {
        log<level::ERR>("Failed to read bound device",
                        entry("ERROR=%s", strerror(errno)));
    }
    if (iface != nameout && iface != unboundIface)
    {
        // SO_BINDTODEVICE
        if ((::setsockopt(udpSocket->native_handle(), SOL_SOCKET,
                          SO_BINDTODEVICE, iface.c_str(),
                          iface.size() + 1) == -1))
        {
            log<level::ERR>("Failed to bind to requested interface",
                            entry("ERROR=%s", strerror(errno)));
            return EXIT_FAILURE;
        }
    }
    // cannot be constexpr because it gets passed by address
    const int option_enabled = 1;
    // common socket stuff; set options to get packet info (DST addr)
    ::setsockopt(udpSocket->native_handle(), IPPROTO_IP, IP_PKTINFO,
                 &option_enabled, sizeof(option_enabled));
    ::setsockopt(udpSocket->native_handle(), IPPROTO_IPV6, IPV6_RECVPKTINFO,
                 &option_enabled, sizeof(option_enabled));

    // set the dbus name
    std::string busName = "xyz.openbmc_project.Ipmi.Channel." + iface;
    try
    {
        bus->request_name(busName.c_str());
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("Failed to acquire D-Bus name",
                        entry("NAME=%s", busName.c_str()),
                        entry("ERROR=%s", e.what()));
        return EXIT_FAILURE;
    }
    return 0;
}

int EventLoop::startEventLoop()
{
    // set up boost::asio signal handling
    boost::asio::signal_set signals(*io, SIGINT, SIGTERM);
    signals.async_wait(
        [this](const boost::system::error_code& error, int signalNumber) {
            udpSocket->cancel();
            udpSocket->close();
            io->stop();
        });

    startRmcpReceive();

    io->run();

    return EXIT_SUCCESS;
}

} // namespace eventloop
