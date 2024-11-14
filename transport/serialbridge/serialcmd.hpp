#pragma once
#include <sdbusplus/bus.hpp>
#include <sdbusplus/message.hpp>
#include <sdbusplus/slot.hpp>
#include <stdplus/fd/intf.hpp>

namespace serialbridge
{

using sdbusplus::bus::bus;
using sdbusplus::message::message;
using sdbusplus::slot::slot;

static constexpr auto BM_START = 0xA0;
static constexpr auto BM_STOP = 0xA5;
static constexpr auto BM_HANDSHAKE = 0xA6;
static constexpr auto BM_ESCAPE = 0xAA;

static constexpr auto MSG_IDLE = 0;
static constexpr auto MSG_IN_PROGRESS = 1;

static constexpr auto IPMI_SERIAL_CONNECTION_HEADER_LENGTH = 3;
static constexpr auto IPMI_SERIAL_CHECKSUM_SIZE = 1;
static constexpr auto IPMI_SERIAL_MAX_BUFFER_SIZE = 256;

/**
 * @brief IPMI Serial Message Structure
 */
struct IpmiSerialHeader
{
    uint8_t rsAddr;
    uint8_t rsNetFnLUN;
    uint8_t checksum1;
    uint8_t rqAddr;
    uint8_t rqSeqLUN;
    uint8_t cmd;
} __attribute__((packed));

class SerialChannel
{
  public:
    static constexpr uint8_t netFnShift = 2;
    static constexpr uint8_t lunMask = (1 << netFnShift) - 1;

    SerialChannel(bool debug) :
        verbose(debug), ctx_state(MSG_IDLE), ctx_escape(0) {};

    void write(stdplus::Fd& uart, uint8_t rsAddr, uint8_t rqAddr, uint8_t seq,
               message&& m);
    void read(stdplus::Fd& serial, sdbusplus::bus_t& bus,
              sdbusplus::slot_t& outstanding);
    uint8_t calculateChecksum(std::span<uint8_t> data);
    uint8_t getUnescapedCharact(uint8_t c);
    int consumeIpmiSerialPacket(std::span<uint8_t>& escapedDataBytes,
                                std::vector<uint8_t>& unescapedDataBytes);
    uint8_t processEscapedCharacter(std::vector<uint8_t>& buffer,
                                    const std::vector<uint8_t>& data);

  private:
    bool verbose;
    uint8_t ctx_state;
    uint8_t ctx_escape;
    std::vector<uint8_t> requestBuffer;
    std::vector<uint8_t> responseBuffer;
};

} // namespace serialbridge
