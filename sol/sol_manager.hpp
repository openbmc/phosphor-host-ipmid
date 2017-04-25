#pragma once

#include <map>
#include <memory>
#include "console_buffer.hpp"
#include "session.hpp"
#include "sol_context.hpp"

namespace sol
{

constexpr size_t MAX_PAYLOAD_INSTANCES = 16;
constexpr size_t MAX_PAYLOAD_SIZE = 255;
constexpr uint8_t MAJOR_VERSION = 0x01;
constexpr uint8_t MINOR_VERSION = 0x00;

constexpr char CONSOLE_SOCKET_PATH[] = "\0obmc-console";
constexpr size_t CONSOLE_SOCKET_PATH_LEN = sizeof(CONSOLE_SOCKET_PATH) - 1;

using Instance = uint8_t;

/** @struct CustomFD
 *
 *  RAII wrapper for file descriptor.
 */
struct CustomFD
{
    CustomFD(const CustomFD&) = delete;
    CustomFD& operator=(const CustomFD&) = delete;
    CustomFD(CustomFD&&) = delete;
    CustomFD& operator=(CustomFD&&) = delete;

    CustomFD(int fd) :
        fd(fd) {}

    ~CustomFD();

    int operator()() const
    {
        return fd;
    }

    private:
        int fd = -1;
};


/** @class Manager
 *
 *  Manager class acts a manager for the SOL payload instances and provides
 *  interfaces to start a payload instance, stop a payload instance and get
 *  reference to the context object.
 */
class Manager
{
    public:

        /** @brief SOL Payload Instance is the key for the map, the value is the
         *         SOL context.
         */
        using SOLPayloadMap = std::map<Instance, std::unique_ptr<Context>>;

        Manager() = default;
        ~Manager() = default;
        Manager(const Manager&) = delete;
        Manager& operator=(const Manager&) = delete;
        Manager(Manager&&) = default;
        Manager& operator=(Manager&&) = default;

        /** @brief Host Console Buffer. */
        ConsoleData dataBuffer;


        /** @brief Character Accumulate Interval
         *
         *  Character Accumulate Interval in 5 ms increments, 1-based. This sets
         *  the typical amount of time that the BMC will wait before
         *  transmitting a partial SOL character data packet. (Where a partial
         *  packet is defined as a packet that has fewer characters to transmit
         *  than the number of characters specified by the character send
         *  threshold. This parameter can be modified by the set SOL
         *  configuration parameters command.
         */
        uint8_t accumulateInterval = 20;

        /** @brief Character Send Threshold
         *
         *  The BMC will automatically send an SOL character data packet
         *  containing this number of characters as soon as this number of
         *  characters (or greater) has been accepted from the baseboard serial
         *  controller into the BMC. This provides a mechanism to tune the
         *  buffer to reduce latency to when the first characters are received
         *  after an idle interval. In the degenerate case, setting this value
         *  to a ‘1’ would cause the BMC to send a packet as soon as the first
         *  character was received. This parameter can be modified by the set
         *  SOL configuration parameters command.
         */
        uint8_t sendThreshold = 1;

        /** @brief Retry Count
         *
         *  1-based. 0 = no retries after packet is transmitted. Packet will be
         *  dropped if no ACK/NACK received by time retries expire. The maximum
         *  value for retry count is 7. This parameter can be modified by the
         *  set SOL configuration parameters command.
         */
        uint8_t retryCount = 7;

        /** @brief Retry Interval
         *
         *  Retry Interval, 1-based. Retry Interval in 10 ms increments. Sets
         *  the time that the BMC will wait before the first retry and the time
         *  between retries when sending SOL packets to the remote console. 00h
         *  indicates retries sent back-to-back. This parameter can be modified
         *  by the set SOL configuration parameters command.
         */
        uint8_t retryThreshold = 10;

        /** @brief Start a SOL payload instance.
         *
         *  Starting a payload instance involves creating the context object,
         *  add the accumulate interval timer and retry interval timer to the
         *  event loop.
         *
         *  @param[in] payloadInstance - SOL payload instance.
         *  @param[in] sessionID - BMC session ID.
         */
        void startPayloadInstance(uint8_t payloadInstance,
                                  session::SessionID sessionID);

        /** @brief Stop SOL payload instance.
         *
         *  Stopping a payload instance involves stopping and removing the
         *  accumulate interval timer and retry interval timer from the event
         *  loop, delete the context object.
         *
         *  @param[in] payloadInstance - SOL payload instance
         */
        void stopPayloadInstance(uint8_t payloadInstance);

        /** @brief Get SOL Context by Payload Instance.
         *
         *  @param[in] payloadInstance - SOL payload instance.
         *
         *  @return reference to the SOL payload context.
         */
        Context& getContext(uint8_t payloadInstance)
        {
            auto iter = payloadMap.find(payloadInstance);

            if (iter != payloadMap.end())
            {
                return *(iter->second);
            }

            std::string msg = "Invalid SOL payload instance " + payloadInstance;
            throw std::runtime_error(msg.c_str());
         }

        /** @brief Get SOL Context by Session ID.
         *
         *  @param[in] sessionID - IPMI Session ID.
         *
         *  @return reference to the SOL payload context.
         */
        Context& getContext(session::SessionID sessionID)
        {
            for (const auto& kv : payloadMap)
            {
                if (kv.second->sessionID == sessionID)
                {
                    return *kv.second;
                }
            }

            std::string msg = "Invalid SOL SessionID " + sessionID;
            throw std::runtime_error(msg.c_str());
        }

        /** @brief Check if SOL payload is active.
         *
         *  @param[in] payloadInstance - SOL payload instance.
         *
         *  @return true if the instance is active and false it is not active.
         */
        auto isPayloadActive(uint8_t payloadInstance) const
        {
            return (0 != payloadMap.count(payloadInstance));
        }

        /** @brief Write data to the host console unix socket.
         *
         *  @param[in] input - Data from the remote console.
         *
         *  @return 0 on success and errno on failure.
         */
        int writeConsoleSocket(const Buffer& input) const;

    private:
        SOLPayloadMap payloadMap;

        /** @brief File descriptor for the host console. */
        std::unique_ptr<CustomFD> consoleFD = nullptr;

        /** @brief Initialize the host console file descriptor. */
        void initHostConsoleFd();
};

} //namespace sol
