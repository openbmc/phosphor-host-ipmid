#include "dbus-sdr/fruwrite.hpp"

#include <gtest/gtest.h>

namespace ipmi::storage
{

TEST(FruProcessing, MinimalReproducer)
{
    std::vector<uint8_t> fru{1, 0, 0, 0, 0, 0xff, 0, 0};
    const auto original = fru;
    EXPECT_FALSE(processFruWrite(fru, 0, original));
    EXPECT_EQ(fru, original);
}

TEST(FruProcessing, ShortCommonHeader)
{
    std::vector<uint8_t> fru;
    EXPECT_FALSE(processFruWrite(fru, 0, {1, 0, 0}));
    EXPECT_EQ(fru, (std::vector<uint8_t>{1, 0, 0}));
}

TEST(FruProcessing, TruncatedRecordHeaders)
{
    for (size_t length = 0; length < 5; ++length)
    {
        std::vector<uint8_t> fru{1, 0, 0, 0, 0, 1, 0, 0};
        fru.resize(8 + length);
        const auto original = fru;
        EXPECT_FALSE(processFruWrite(fru, 0, original)) << length;
        EXPECT_EQ(fru, original);
    }
}

TEST(FruProcessing, TruncatedPayload)
{
    std::vector<uint8_t> fru{1, 0, 0, 0, 0, 1, 0, 0, 0, 0x80, 4, 0, 0, 1, 2, 3};
    const auto original = fru;
    EXPECT_FALSE(processFruWrite(fru, 0, original));
    EXPECT_EQ(fru, original);
}

TEST(FruProcessing, MissingEndMarker)
{
    std::vector<uint8_t> fru{1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0};
    const auto original = fru;
    EXPECT_FALSE(processFruWrite(fru, 0, original));
}

TEST(FruProcessing, CompleteRecord)
{
    std::vector<uint8_t> fru{1, 0, 0, 0, 0, 1, 0, 0, 0, 0x80, 0, 0, 0};
    const auto original = fru;
    EXPECT_TRUE(processFruWrite(fru, 0, original));
    EXPECT_EQ(fru, original);
}

TEST(FruProcessing, RecordChainWithPayload)
{
    std::vector<uint8_t> fru{1, 0, 0,    0,    0, 1,    0, 0, 0, 0,   2,
                             0, 0, 0xaa, 0xbb, 0, 0x80, 1, 0, 0, 0xcc};
    const auto original = fru;
    EXPECT_TRUE(processFruWrite(fru, 0, original));
    EXPECT_EQ(fru, original);
}

TEST(FruProcessing, UsesMultiRecordOffsetNotLargestOffset)
{
    std::vector<uint8_t> fru{1, 0, 0, 0, 2, 1, 0, 0, 0, 0x80, 0, 0, 0};
    const auto original = fru;
    EXPECT_TRUE(processFruWrite(fru, 0, original));
}

TEST(FruProcessing, PartialWriteOfCompleteRecord)
{
    std::vector<uint8_t> fru{1, 0, 0, 0, 0, 1, 0, 0, 0, 0x80, 0, 0, 0};
    const auto original = fru;
    EXPECT_FALSE(processFruWrite(fru, 0, {1}));
    EXPECT_EQ(fru, original);
}

TEST(FruProcessing, CompletingPayloadExtendsBuffer)
{
    std::vector<uint8_t> fru{1, 0, 0, 0, 0, 1, 0, 0, 0, 0x80, 2, 0, 0};
    auto expected = fru;
    expected.insert(expected.end(), {0xaa, 0xbb});
    EXPECT_TRUE(processFruWrite(fru, 13, {0xaa, 0xbb}));
    EXPECT_EQ(fru, expected);
}

TEST(FruProcessing, ProductArea)
{
    std::vector<uint8_t> fru{1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0};
    const auto original = fru;
    EXPECT_TRUE(processFruWrite(fru, 0, original));
    EXPECT_EQ(fru, original);
}

} // namespace ipmi::storage
