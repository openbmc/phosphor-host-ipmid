#pragma once
#include <sdbusplus/bus.hpp>
#include <sdbusplus/message.hpp>
#include <sdbusplus/slot.hpp>
#include <stdplus/fd/intf.hpp>

#define BM_START 0xA0
#define BM_STOP 0xA5
#define BM_HANDSHAKE 0xA6
#define BM_ESCAPE 0xAA

#define MSG_IDLE 0
#define MSG_IN_PROGRESS 1

#define IPMI_SERIAL_CONNECTION_HEADER_LENGTH 3
#define IPMI_SERIAL_CHECKSUM_SIZE 1
#define IPMI_SERIAL_MAX_BUFFER_SIZE 256

namespace serialbridge
{

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
    uint8_t data[];
};

void write(stdplus::Fd& serial, sdbusplus::message_t&& m);
void read(stdplus::Fd& serial, sdbusplus::bus_t& bus,
          sdbusplus::slot_t& outstanding);
void setVerbose(bool enable);

uint8_t calculateChecksum(uint8_t* data, uint8_t length);
uint8_t getEscapedCharact(uint8_t c);
uint8_t getUnescapedCharact(uint8_t c);
int consumeIpmiSerialPacket(std::span<uint8_t>& escapedDataBytes,
                            std::vector<uint8_t>& unescapedDataBytes);
uint8_t processEscapedCharacter(std::vector<uint8_t>& buffer, uint8_t c);

} // namespace serialbridge
