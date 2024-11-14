#pragma once
#include <sdbusplus/bus.hpp>
#include <sdbusplus/message.hpp>
#include <sdbusplus/slot.hpp>
#include <stdplus/fd/intf.hpp>

namespace serialbridge
{

static constexpr auto bmStart = 0xA0;
static constexpr auto bmStop = 0xA5;
static constexpr auto bmHandshake = 0xA6;
static constexpr auto bmEscape = 0xAA;

static constexpr auto ipmiSerialConnectionHeaderLength = 3;
static constexpr auto ipmiSerialChecksumSize = 1;
static constexpr auto ipmiSerialMaxBufferSize = 256;

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

    SerialChannel(bool debug) : verbose(debug), msgState(MsgState::msgIdle) {};

    int write(stdplus::Fd& uart, uint8_t rsAddr, uint8_t rqAddr, uint8_t seq,
              sdbusplus::message_t&& m);
    void read(stdplus::Fd& serial, sdbusplus::bus_t& bus,
              sdbusplus::slot_t& outstanding);
    uint8_t calculateChecksum(std::span<uint8_t> data);
    uint8_t getUnescapedCharacter(uint8_t c);
    int consumeIpmiSerialPacket(std::span<uint8_t>& escapedDataBytes,
                                std::vector<uint8_t>& unescapedDataBytes);
    uint8_t processEscapedCharacter(std::vector<uint8_t>& buffer,
                                    const std::vector<uint8_t>& data);

  private:
    bool verbose;
    enum class MsgState
    {
        msgIdle = 0,
        msgInProgress,
        msgInEscape,
    };
    MsgState msgState;
    std::vector<uint8_t> requestBuffer;
    std::vector<uint8_t> responseBuffer;
};

} // namespace serialbridge
