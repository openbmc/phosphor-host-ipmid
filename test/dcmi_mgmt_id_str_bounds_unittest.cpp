#include <ipmid/api.hpp>

#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

// Under test: setMgmntCtrlIdStr() from dcmihandler.cpp (libipmi20).
// Previously, count == 0 with an empty data vector was accepted, and the
// handler then called data.back() (UB on an empty vector) and, on the
// '\0' path, data.resize(count - 1) (uint8 zero minus one wraps). The
// handler must reject a zero count before touching data.
ipmi::RspType<uint8_t> setMgmntCtrlIdStr(ipmi::Context::ptr& ctx,
                                         uint8_t offset, uint8_t count,
                                         std::vector<char> data);

namespace
{

TEST(DcmiSetMgmtCtrlIdStrTest, ZeroCountRejectedWithoutCrash)
{
    ipmi::Context::ptr ctx{}; // unused on the rejection path
    auto rsp = setMgmntCtrlIdStr(ctx, /*offset=*/0, /*count=*/0, {});
    EXPECT_EQ(std::get<0>(rsp), ipmi::ccReqDataLenInvalid);
}

TEST(DcmiSetMgmtCtrlIdStrTest, ZeroCountNonEmptyDataRejected)
{
    ipmi::Context::ptr ctx{};
    auto rsp = setMgmntCtrlIdStr(ctx, /*offset=*/0, /*count=*/0, {'x'});
    EXPECT_EQ(std::get<0>(rsp), ipmi::ccReqDataLenInvalid);
}

TEST(DcmiSetMgmtCtrlIdStrTest, CountDataSizeMismatchRejected)
{
    ipmi::Context::ptr ctx{};
    auto rsp = setMgmntCtrlIdStr(ctx, /*offset=*/0, /*count=*/3, {'x', 'y'});
    EXPECT_EQ(std::get<0>(rsp), ipmi::ccReqDataLenInvalid);
}

TEST(DcmiSetMgmtCtrlIdStrTest, ValidNonTerminalWriteAccepted)
{
    // offset 0 and no trailing '\0' byte: the handler appends the data and
    // returns success without touching D-Bus or the hostname readback path.
    ipmi::Context::ptr ctx{};
    auto rsp =
        setMgmntCtrlIdStr(ctx, /*offset=*/0, /*count=*/3, {'b', 'm', 'c'});
    EXPECT_EQ(std::get<0>(rsp), ipmi::ccSuccess);
}

TEST(DcmiSetMgmtCtrlIdStrTest, ValidTerminalWriteOfEmptyStringAccepted)
{
    // The legal 'clear the string' flow per DCMI 1.5 6.4.5.2: a single
    // NUL byte at offset 0. Exercises the data.resize(count - 1) path
    // with count == 1 (resize(0)), the completion the zero-count path
    // used to reach as resize(SIZE_MAX) before the fix.
    ipmi::Context::ptr ctx{};
    auto rsp = setMgmntCtrlIdStr(ctx, /*offset=*/0, /*count=*/1, {'\0'});
    EXPECT_EQ(std::get<0>(rsp), ipmi::ccSuccess);
}

TEST(DcmiSetMgmtCtrlIdStrTest, NonTerminalWriteAtMaxLengthRejected)
{
    // A non-terminal write that would end exactly at the maximum length
    // has no room left for the required terminator and must be rejected
    // (parm out of range), pinning the 'last byte must be the NUL' rule.
    ipmi::Context::ptr ctx{};
    const uint8_t maxLen = 64;
    auto rsp = setMgmntCtrlIdStr(ctx, /*offset=*/maxLen - 3, /*count=*/3,
                                 {'x', 'y', 'z'});
    EXPECT_EQ(std::get<0>(rsp), ipmi::ccParmOutOfRange);
}

} // namespace
