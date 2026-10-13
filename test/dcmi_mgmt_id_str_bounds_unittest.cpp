#include <ipmid/api.hpp>

#include <cstdint>
#include <string>
#include <vector>

#include <gtest/gtest.h>

// Definitions for the test-controllable D-Bus property store declared
// extern in the stub.
namespace ipmi
{
std::string setDbusPropertyStubValue;
std::string getDbusPropertyStubValue;
} // namespace ipmi

class DcmiSetMgmtCtrlIdStrTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        ipmi::setDbusPropertyStubValue.clear();
        ipmi::getDbusPropertyStubValue.clear();
    }
};

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

TEST_F(DcmiSetMgmtCtrlIdStrTest, ZeroCountRejectedWithoutCrash)
{
    ipmi::Context::ptr ctx{}; // unused on the rejection path
    auto rsp = setMgmntCtrlIdStr(ctx, /*offset=*/0, /*count=*/0, {});
    EXPECT_EQ(std::get<0>(rsp), ipmi::ccReqDataLenInvalid);
}

TEST_F(DcmiSetMgmtCtrlIdStrTest, ZeroCountNonEmptyDataRejected)
{
    ipmi::Context::ptr ctx{};
    auto rsp = setMgmntCtrlIdStr(ctx, /*offset=*/0, /*count=*/0, {'x'});
    EXPECT_EQ(std::get<0>(rsp), ipmi::ccReqDataLenInvalid);
}

TEST_F(DcmiSetMgmtCtrlIdStrTest, CountDataSizeMismatchRejected)
{
    ipmi::Context::ptr ctx{};
    auto rsp = setMgmntCtrlIdStr(ctx, /*offset=*/0, /*count=*/3, {'x', 'y'});
    EXPECT_EQ(std::get<0>(rsp), ipmi::ccReqDataLenInvalid);
}

TEST_F(DcmiSetMgmtCtrlIdStrTest, ValidNonTerminalWriteAccepted)
{
    // offset 0 and no trailing '\0' byte: the handler splices the data
    // over the current (empty) hostname and commits it on this write.
    ipmi::Context::ptr ctx{};
    auto rsp =
        setMgmntCtrlIdStr(ctx, /*offset=*/0, /*count=*/3, {'b', 'm', 'c'});
    EXPECT_EQ(std::get<0>(rsp), ipmi::ccSuccess);
    EXPECT_EQ(ipmi::setDbusPropertyStubValue, "bmc");
}

TEST_F(DcmiSetMgmtCtrlIdStrTest, ValidTerminalWriteOfEmptyStringAccepted)
{
    // The legal 'clear the string' flow per DCMI 1.5 6.4.5.2: a single
    // NUL byte at offset 0. Exercises the data.resize(count - 1) path
    // with count == 1 (resize(0)), the completion the zero-count path
    // used to reach as resize(SIZE_MAX) before the fix.
    ipmi::Context::ptr ctx{};
    auto rsp = setMgmntCtrlIdStr(ctx, /*offset=*/0, /*count=*/1, {'\0'});
    EXPECT_EQ(std::get<0>(rsp), ipmi::ccSuccess);
}

TEST_F(DcmiSetMgmtCtrlIdStrTest, NonTerminalWriteAtMaxLengthRejected)
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

TEST_F(DcmiSetMgmtCtrlIdStrTest, TerminalWriteSplicesCurrentHostname)
{
    // Stateful splice: a non-terminal write then a terminal write must
    // commit exactly the spliced string, read back from D-Bus between
    // calls (no in-process accumulator).
    ipmi::Context::ptr ctx{};
    ipmi::getDbusPropertyStubValue = "oldhost";
    ipmi::setDbusPropertyStubValue.clear();

    auto rsp1 =
        setMgmntCtrlIdStr(ctx, /*offset=*/0, /*count=*/4, {'n', 'e', 'w', '0'});
    // '0' chosen non-NUL so this is a non-terminal write
    ASSERT_EQ(std::get<0>(rsp1), ipmi::ccSuccess);
    // The splice is committed on every write (setAssetTag pattern).
    EXPECT_EQ(ipmi::setDbusPropertyStubValue, "new0");

    // What the next call reads back reflects the committed splice.
    ipmi::getDbusPropertyStubValue = ipmi::setDbusPropertyStubValue;
    auto rsp2 = setMgmntCtrlIdStr(ctx, /*offset=*/4, /*count=*/2, {'x', '\0'});
    ASSERT_EQ(std::get<0>(rsp2), ipmi::ccSuccess);
    EXPECT_EQ(std::get<0>(std::get<1>(rsp2).value()), 5);
    EXPECT_EQ(ipmi::setDbusPropertyStubValue, "new0x");
}

TEST_F(DcmiSetMgmtCtrlIdStrTest, AbandonedWriteDoesNotPolluteNextSession)
{
    // The regression this change exists for: session A abandons a
    // partial write, session B (a fresh offset-0 terminal write) must
    // NOT have A's bytes prepended to what it commits. With the old
    // function-local static accumulator, B committed "aaaab" here.
    ipmi::Context::ptr ctx{};

    // Session A: non-terminal partial write at offset 0.
    ipmi::getDbusPropertyStubValue = "";
    auto rspA =
        setMgmntCtrlIdStr(ctx, /*offset=*/0, /*count=*/4, {'a', 'a', 'a', 'a'});
    ASSERT_EQ(std::get<0>(rspA), ipmi::ccSuccess);

    // Session B: fresh terminal write at offset 0, reading back what
    // session A actually committed to D-Bus ("aaaa" on a real system;
    // the readback-then-truncate-at-offset-0 is the behavior under test).
    ipmi::getDbusPropertyStubValue = "aaaa";
    auto rspB = setMgmntCtrlIdStr(ctx, /*offset=*/0, /*count=*/2, {'b', '\0'});
    ASSERT_EQ(std::get<0>(rspB), ipmi::ccSuccess);
    EXPECT_EQ(ipmi::setDbusPropertyStubValue, "b");
}

TEST_F(DcmiSetMgmtCtrlIdStrTest, InteriorNulTerminalRejected)
{
    // A NUL before the final byte would be silently truncated by the
    // D-Bus string marshalling (strlen), breaking write/read
    // round-trip fidelity; rejected as invalid request data length.
    ipmi::Context::ptr ctx{};
    ipmi::getDbusPropertyStubValue = "";
    auto rsp = setMgmntCtrlIdStr(ctx, /*offset=*/0, /*count=*/4,
                                 {'a', '\0', 'b', '\0'});
    EXPECT_EQ(std::get<0>(rsp), ipmi::ccReqDataLenInvalid);
    EXPECT_TRUE(ipmi::setDbusPropertyStubValue.empty());
}

TEST_F(DcmiSetMgmtCtrlIdStrTest, InteriorNulNonTerminalRejected)
{
    ipmi::Context::ptr ctx{};
    ipmi::getDbusPropertyStubValue = "";
    auto rsp = setMgmntCtrlIdStr(ctx, /*offset=*/0, /*count=*/4,
                                 {'a', '\0', 'b', 'c'});
    EXPECT_EQ(std::get<0>(rsp), ipmi::ccReqDataLenInvalid);
    EXPECT_TRUE(ipmi::setDbusPropertyStubValue.empty());
}

TEST_F(DcmiSetMgmtCtrlIdStrTest, AppendAtExactEndAccepted)
{
    // offset == current length is a pure append, the valid side of the
    // offset fence.
    ipmi::Context::ptr ctx{};
    ipmi::getDbusPropertyStubValue = "abc";
    auto rsp = setMgmntCtrlIdStr(ctx, /*offset=*/3, /*count=*/2, {'d', '\0'});
    ASSERT_EQ(std::get<0>(rsp), ipmi::ccSuccess);
    EXPECT_EQ(ipmi::setDbusPropertyStubValue, "abcd");
}

TEST_F(DcmiSetMgmtCtrlIdStrTest, MidStringTerminalTruncateAccepted)
{
    // A terminal write at 0 < offset < len truncates the tail and
    // commits, matching the truncate-at-offset splice semantics.
    ipmi::Context::ptr ctx{};
    ipmi::getDbusPropertyStubValue = "abcdef";
    auto rsp = setMgmntCtrlIdStr(ctx, /*offset=*/2, /*count=*/2, {'x', '\0'});
    ASSERT_EQ(std::get<0>(rsp), ipmi::ccSuccess);
    EXPECT_EQ(std::get<0>(std::get<1>(rsp).value()), 3);
    EXPECT_EQ(ipmi::setDbusPropertyStubValue, "abx");
}

TEST_F(DcmiSetMgmtCtrlIdStrTest, CountAboveMaxBytesRejected)
{
    // Field x (too-large, edge-valid) matrix: count=17 > maxBytes=16.
    ipmi::Context::ptr ctx{};
    std::vector<char> seventeen(17, 'x');
    auto rsp = setMgmntCtrlIdStr(ctx, /*offset=*/0, /*count=*/17, seventeen);
    EXPECT_EQ(std::get<0>(rsp), ipmi::ccParmOutOfRange);
}

TEST_F(DcmiSetMgmtCtrlIdStrTest, CountAtMaxBytesAccepted)
{
    // Edge-valid: count == maxBytes == 16 exactly.
    ipmi::Context::ptr ctx{};
    std::vector<char> sixteen(15, 'x');
    sixteen.push_back('\0');
    ipmi::getDbusPropertyStubValue = "";
    auto rsp = setMgmntCtrlIdStr(ctx, /*offset=*/0, /*count=*/16, sixteen);
    EXPECT_EQ(std::get<0>(rsp), ipmi::ccSuccess);
    EXPECT_EQ(static_cast<size_t>(std::get<0>(std::get<1>(rsp).value())), 15u);
}

TEST_F(DcmiSetMgmtCtrlIdStrTest, OffsetAboveMaxLenRejected)
{
    // Field x (too-large, edge-valid) matrix: offset=65 > maxCtrlIdStrLen=64.
    ipmi::Context::ptr ctx{};
    auto rsp = setMgmntCtrlIdStr(ctx, /*offset=*/65, /*count=*/1, {'x'});
    EXPECT_EQ(std::get<0>(rsp), ipmi::ccParmOutOfRange);
}

TEST_F(DcmiSetMgmtCtrlIdStrTest, OffsetAtMaxLenMinusCountRejected)
{
    // offset=63, count=2 non-terminal lands past the last legal byte
    // (63+2 > 64); the range gate must reject.
    ipmi::Context::ptr ctx{};
    auto rsp = setMgmntCtrlIdStr(ctx, /*offset=*/63, /*count=*/2, {'x', 'y'});
    EXPECT_EQ(std::get<0>(rsp), ipmi::ccParmOutOfRange);
}

TEST_F(DcmiSetMgmtCtrlIdStrTest, OffsetPastCurrentHostnameRejected)
{
    // offset beyond the current length no longer zero-pads (the old
    // resize(offset) embedded NULs the D-Bus 's' type cannot carry);
    // it is rejected the same way setAssetTag rejects it.
    ipmi::Context::ptr ctx{};
    ipmi::getDbusPropertyStubValue = "abc";
    auto rsp = setMgmntCtrlIdStr(ctx, /*offset=*/10, /*count=*/2, {'x', '\0'});
    EXPECT_EQ(std::get<0>(rsp), ipmi::ccParmOutOfRange);
    EXPECT_TRUE(ipmi::setDbusPropertyStubValue.empty());
}

} // namespace
