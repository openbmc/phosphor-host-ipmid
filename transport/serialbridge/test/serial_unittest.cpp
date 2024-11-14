#include <transport/serialbridge/serialcmd.hpp>

#include <gtest/gtest.h>

namespace serialbridge
{

/**
 * @brief Table of special characters
 */
std::unordered_map<uint8_t, uint8_t> testsets = {
    {BM_START, 0xB0},     /* start */
    {BM_STOP, 0xB5},      /* stop */
    {BM_HANDSHAKE, 0xB6}, /* packet handshake */
    {BM_ESCAPE, 0xBA},    /* data escape */
    {0x1B, 0x3B}          /* escape */
};

TEST(TestSpecialCharact, getUnescapedCharact)
{
    uint8_t c;
    auto channel = std::make_shared<SerialChannel>(0);

    for (const auto& set : testsets)
    {
        c = channel->getUnescapedCharact(set.second);
        ASSERT_EQ(c, set.first);
    }
}

TEST(TestSpecialCharact, processEscapedCharacter)
{
    std::vector<uint8_t> buffer;
    uint8_t unescaped = 0xd0;
    auto channel = std::make_shared<SerialChannel>(0);

    channel->processEscapedCharacter(buffer, std::vector<uint8_t>{BM_START});

    ASSERT_EQ(buffer.at(0), BM_ESCAPE);
    ASSERT_EQ(buffer.at(1), testsets.at(BM_START));

    buffer.clear();
    channel->processEscapedCharacter(buffer, std::vector<uint8_t>{unescaped});

    ASSERT_EQ(buffer.at(0), unescaped);
}

TEST(TestChecksum, calculateChecksum)
{
    std::array<uint8_t, 5> dataBytes{0x01, 0x10, 0x60, 0xf0, 0x50};
    auto channel = std::make_shared<SerialChannel>(0);

    uint8_t checksum =
        channel->calculateChecksum(std::span<uint8_t>(dataBytes));

    checksum += (~checksum) + 1;
    ASSERT_EQ(checksum, 0);
}

TEST(TestIpmiSerialPacket, consumeIpmiSerialPacket)
{
    std::vector<uint8_t> dataBytes{BM_START, 0x20, 0x18, 0xc8, 0x81,
                                   0xc,      0x46, 0x01, 0x2c, BM_STOP};
    std::vector<uint8_t> dataBytesSplit1{BM_START, 0x20, 0x18, 0xc8};
    std::vector<uint8_t> dataBytesSplit2{0x81, 0xc, 0x46, 0x01, 0x2c, BM_STOP};
    std::span<uint8_t> input(dataBytes);
    std::span<uint8_t> input1(dataBytesSplit1);
    std::span<uint8_t> input2(dataBytesSplit2);
    std::vector<uint8_t> output;

    auto channel = std::make_shared<SerialChannel>(0);

    auto result = channel->consumeIpmiSerialPacket(input, output);

    ASSERT_EQ(result, true);

    output.clear();
    result = channel->consumeIpmiSerialPacket(input1, output);
    ASSERT_EQ(result, false);
    result = channel->consumeIpmiSerialPacket(input2, output);
    ASSERT_EQ(result, true);
}

} // namespace serialbridge
