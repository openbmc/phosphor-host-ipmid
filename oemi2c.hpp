#pragma once

#include "host-ipmid/oemopenbmc.hpp"
#include "host-ipmid/oemrouter.hpp"

#include <cstdint>
#include <memory>

#include "host-ipmid/ipmid-api.h"

namespace oem
{
namespace google
{
/*
 * This is the Google, Inc. IANA OEM Number
 */
constexpr Number googOemNumber = 11129;
} // namespace google

namespace i2c
{
/*
 * Request header
 */
enum : size_t // Layout
{
    reqHdrBus = 0,
    reqHdrFlags = 1,
    reqHdrLen = 2,
};

typedef uint8_t BusId;
typedef uint8_t ReqFlags;
enum : ReqFlags
{
    flagUsePec = 1 << 7,
};

/*
 * Request step.
 */
enum : size_t // Layout
{
    stepHdrDevAndDir = 0,
    stepHdrFlags = 1,
    stepHdrParm = 2,
    stepHdrLen = 3,
};

typedef uint8_t DevAddr;
typedef uint8_t StepFlags;
enum : StepFlags
{
    flagRecvLen = 1 << 7,
    flagNoStart = 1 << 6,
};

// So far 2 steps suffics, so 4 should be safe.
constexpr size_t maxSteps = 4;

// Currently we specify 32 byte payload limit;
// but for block read with PEC that entails 34 total bytes.
constexpr size_t largestReply = 34;

} // namespace i2c

class OemI2c
{
  public:
    void registerWith(Router* oemRouter);
    ipmi_ret_t transfer(ipmi_cmd_t cmd, const uint8_t* reqBuf,
                        uint8_t* replyBuf, size_t* dataLen);
};

} // namespace oem
