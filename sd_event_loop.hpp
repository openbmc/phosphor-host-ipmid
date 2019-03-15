#pragma once

#include "sol/sol_manager.hpp"

#include <systemd/sd-event.h>

#include <boost/asio/io_context.hpp>
#include <chrono>
#include <map>
#include <sdbusplus/asio/connection.hpp>

namespace ipmi
{
namespace rmcpp
{
constexpr uint16_t defaultPort = 623;
} // namespace rmcpp
} // namespace ipmi

namespace eventloop
{

class EventLoop
{
  public:
    explicit EventLoop(std::shared_ptr<boost::asio::io_context> io) : io(io)
    {
    }
    EventLoop() = delete;
    ~EventLoop() = default;
    EventLoop(const EventLoop&) = delete;
    EventLoop& operator=(const EventLoop&) = delete;
    EventLoop(EventLoop&&) = delete;
    EventLoop& operator=(EventLoop&&) = delete;

    /** @brief Initialise the event loop and add the handler for incoming
     *         IPMI packets.
     *
     *  @return EXIT_SUCCESS on success and EXIT_FAILURE on failure.
     */
    int startEventLoop();

    /** @brief Set up the socket (if systemd has not already) and
     *         make sure that the bus name matches the specified channel
     */
    int setupSocket(std::shared_ptr<sdbusplus::asio::connection>& bus,
                    std::string iface,
                    uint16_t reqPort = ipmi::rmcpp::defaultPort);

  private:
    /** @brief async handler for incoming udp packets */
    void handleRmcpPacket();

    /** @brief register the async handler for incoming udp packets */
    void startRmcpReceive();

    /** @brief boost::asio io context to run with
     */
    std::shared_ptr<boost::asio::io_context> io;

    /** @brief boost::asio udp socket
     */
    std::shared_ptr<boost::asio::ip::udp::socket> udpSocket = nullptr;
};

} // namespace eventloop
