#include <apphandler.hpp>

#include <gtest/gtest.h>

TEST(parseSessionInputPayloadTest, ValidObjectPath)
{
    uint32_t sessionId = 0;
    uint8_t sessionHandle = 0;
    std::string objectPath =
        "/xyz/openbmc_project/ipmi/session/eth0/12a4567d_8a";

    EXPECT_TRUE(
        parseCloseSessionInputPayload(objectPath, sessionId, sessionHandle));
    EXPECT_EQ(0x12a4567d, sessionId);
    EXPECT_EQ(0x8a, sessionHandle);
}

TEST(parseSessionInputPayloadTest, InValidObjectPath)
{
    uint32_t sessionId = 0;
    uint8_t sessionHandle = 0;
    std::string objectPath = "/xyz/openbmc_project/ipmi/session/eth0/12a4567d";

    EXPECT_FALSE(
        parseCloseSessionInputPayload(objectPath, sessionId, sessionHandle));
}

TEST(parseSessionInputPayloadTest, NoObjectPath)
{
    uint32_t sessionId = 0;
    uint8_t sessionHandle = 0;
    std::string objectPath;

    EXPECT_FALSE(
        parseCloseSessionInputPayload(objectPath, sessionId, sessionHandle));
}
