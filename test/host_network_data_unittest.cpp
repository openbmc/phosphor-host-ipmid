#include <netinet/in.h>

#include <ipmid/api.hpp>
#include <ipmid/message.hpp>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

std::string getAddrStr(uint8_t family, uint8_t* data, uint8_t offset,
                       uint8_t addrSize);
ipmi::Cc setHostNetworkData(ipmi::message::Payload& data);

namespace
{

// Build a request payload that reaches the addrSize check in
// setHostNetworkData(): valid cookie at offset 1..4, non-trapping version
// bytes at offset 5..6, addrSize at offset 8, and enough trailing bytes to
// satisfy the preceding length checks.
ipmi::message::Payload makeHostNetworkPayload(uint8_t addrSize,
                                              size_t totalLen = 64)
{
    ipmi::SecureBuffer req = {0x80, 0x21, 0x70, 0x62,    0x21,
                              0x00, 0x02, 0x06, addrSize};
    if (req.size() < totalLen)
    {
        req.resize(totalLen, 0x41);
    }
    return ipmi::message::Payload(std::move(req));
}

TEST(GetAddrStr, Ipv4AddressIsConverted)
{
    std::vector<uint8_t> data = {0xff, 10, 1, 2, 3};
    EXPECT_EQ("10.1.2.3", getAddrStr(AF_INET, data.data(), 1, 4));
}

TEST(GetAddrStr, Ipv6AddressIsConverted)
{
    // Leading 0xff is not part of the address; offset 1 skips it.
    std::vector<uint8_t> data = {0xff, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                 0,    0,    0,    0,    0,    0, 0, 5};
    ASSERT_EQ(17U, data.size());
    EXPECT_EQ("2001:db8::5", getAddrStr(AF_INET6, data.data(), 1, 16));
}

// The address size comes from the request; anything other than the size of
// the address family must be rejected before it is used as a copy length.

TEST(GetAddrStr, Ipv6SizeLargerThanAddressIsRejected)
{
    std::vector<uint8_t> data(255, 0xa5);
    EXPECT_EQ("", getAddrStr(AF_INET6, data.data(), 0, 255));
}

TEST(GetAddrStr, Ipv6SizeOneByteTooLongIsRejected)
{
    std::vector<uint8_t> data(17, 0xa5);
    EXPECT_EQ("", getAddrStr(AF_INET6, data.data(), 0, 17));
}

TEST(GetAddrStr, Ipv6SizeShorterThanAddressIsRejected)
{
    std::vector<uint8_t> data(5, 0xa5);
    EXPECT_EQ("", getAddrStr(AF_INET6, data.data(), 0, 5));
}

TEST(GetAddrStr, Ipv4SizeLargerThanAddressIsRejected)
{
    std::vector<uint8_t> data(16, 0xa5);
    EXPECT_EQ("", getAddrStr(AF_INET, data.data(), 0, 16));
}

TEST(SetHostNetworkData, OversizedAddrSizeIsRejected)
{
    auto payload = makeHostNetworkPayload(255, 17 + 255 + 1 + 255);
    EXPECT_EQ(ipmi::ccInvalidFieldRequest, setHostNetworkData(payload));
}

TEST(SetHostNetworkData, NonStandardAddrSizeIsRejected)
{
    auto payload = makeHostNetworkPayload(17, 64);
    EXPECT_EQ(ipmi::ccInvalidFieldRequest, setHostNetworkData(payload));
}

TEST(SetHostNetworkData, ZeroAddrSizeIsRejected)
{
    auto payload = makeHostNetworkPayload(0, 64);
    EXPECT_EQ(ipmi::ccInvalidFieldRequest, setHostNetworkData(payload));
}

} // namespace
