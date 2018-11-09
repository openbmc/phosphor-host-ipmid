#pragma once

#include <boost/asio/ip/udp.hpp>
#include <memory>
#include <string>
#include <tuple>
#include <vector>

namespace udpsocket
{

/** @class Channel
 *
 *  @brief Provides encapsulation for UDP socket operations like Read, Peek,
 *         Write, Remote peer's IP Address and Port.
 */
class Channel
{
  public:
    Channel() = delete;
    ~Channel() = default;
    Channel(const Channel& right) = delete;
    Channel& operator=(const Channel& right) = delete;
    Channel(Channel&&) = delete;
    Channel& operator=(Channel&&) = delete;

    /**
     * @brief Constructor
     *
     * Initialize the IPMI socket object with the socket descriptor
     *
     * @param [in] pointer to a boost::asio udp socket object
     *
     * @return None
     */
    explicit Channel(std::shared_ptr<boost::asio::ip::udp::socket> socket) :
        socket(socket)
    {
    }

    /**
     * @brief Fetch the IP address of the remote peer
     *
     * Returns the IP address of the remote peer which is connected to this
     * socket
     *
     * @return IP address of the remote peer
     */
    std::string getRemoteAddress() const
    {
        return endpoint.address().to_string();
    }

    /**
     * @brief Fetch the port number of the remote peer
     *
     * Returns the port number of the remote peer
     *
     * @return Port number
     *
     */
    auto getPort() const
    {
        return endpoint.port();
    }

    /**
     * @brief Read the incoming packet
     *
     * Reads the data available on the socket
     *
     * @return A tuple with return code and vector with the buffer
     *         In case of success, the vector is populated with the data
     *         available on the socket and return code is 0.
     *         In case of error, the return code is < 0 and vector is set
     *         to size 0.
     */
    std::tuple<int, std::vector<uint8_t>> read()
    {
        std::vector<uint8_t> packet(socket->available());
        try
        {
            socket->receive_from(boost::asio::buffer(packet), endpoint);
        }
        catch (const boost::system::system_error& e)
        {
            return std::make_tuple(e.code().value(), std::vector<uint8_t>());
        }
        return std::make_tuple(0, packet);
    }

    /**
     *  @brief Write the outgoing packet
     *
     *  Writes the data in the vector to the socket
     *
     *  @param [in] inBuffer
     *      The vector would be the buffer of data to write to the socket.
     *
     *  @return In case of success the return code is 0 and return code is
     *          < 0 in case of failure.
     */
    int write(const std::vector<uint8_t>& inBuffer)
    {
        try
        {
            socket->send_to(boost::asio::buffer(inBuffer), endpoint);
        }
        catch (const boost::system::system_error& e)
        {
            return e.code().value();
        }
        return 0;
    }

    /**
     * @brief Returns file descriptor for the socket
     */
    auto getHandle(void) const
    {
        return socket->native_handle();
    }

  private:
    std::shared_ptr<boost::asio::ip::udp::socket> socket;
    boost::asio::ip::udp::endpoint endpoint{};
};

} // namespace udpsocket
