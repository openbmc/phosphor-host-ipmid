#include "oemi2c.hpp"

#include <errno.h>
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace oem
{
namespace i2c
{

// Instance object.
std::unique_ptr<OemI2c> globalOemI2c;

// Block read (I2C_M_RECV_LEN) reads count byte, then that many bytes,
// then possibly a checksum byte. The specified byte count limit,
// I2C_SMBUS_BLOCK_MAX, is 32, but it seems intractible to prove
// every I2C implementation uses that limit. So to prevent overflow,
// allocate buffers based on the largest possible count byte of 255.
constexpr size_t maxRecvLenBuf = 1 + 255 + 1;
typedef std::array<uint8_t, maxRecvLenBuf> BlockBuf;

struct ParsedStep
{
    const uint8_t* reqData;
    size_t length;
    DevAddr devAddr;
    bool isRead;
    // When nonzero, device supplies count for this step, as in SMBUS block
    // mode. Value will tell driver how many extra bytes to read for entire
    // block: 1 for count byte w/o PEC, 2 if there is also a PEC byte.
    uint16_t blockExtra;
    bool noStart;
};

struct ParsedReq
{
    BusId localbus;
    bool usePec;
    size_t numSteps;
    std::array<ParsedStep, maxSteps> step;
};

static ipmi_ret_t parseReqHdr(const uint8_t* reqBuf, size_t reqLen,
                              size_t* bytesUsed, i2c::ParsedReq* req)
{
    // Request header selects bus & flags for operation;
    // additional bytes beyond are to be interpreted as steps.
    if (reqLen < *bytesUsed + reqHdrLen)
    {
        fprintf(stderr, "i2c::parse reqLen=%zu?\n", reqLen);
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    // Deserialize request header bytes.
    req->localbus = reqBuf[reqHdrBus];
    auto reqFlags = reqBuf[reqHdrFlags];
    *bytesUsed += reqHdrLen;

    // Decode flags.
    req->usePec = !!(reqFlags & flagUsePec);
    return IPMI_CC_OK;
}

static ipmi_ret_t parseReqStep(const uint8_t* reqBuf, size_t reqLen,
                               size_t* bytesUsed, i2c::ParsedReq* req)
{
    size_t bytesLeft = reqLen - *bytesUsed;
    if (req->numSteps >= maxSteps || bytesLeft < stepHdrLen)
    {
        fprintf(stderr, "i2c::parse[%zu] bytesLeft=%zu?\n", req->numSteps,
                bytesLeft);
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    const uint8_t* stepHdr = reqBuf + *bytesUsed;
    auto step = &req->step[req->numSteps++];

    // Deserialize request step header bytes.
    uint8_t devAndDir = stepHdr[stepHdrDevAndDir];
    uint8_t stepFlags = stepHdr[stepHdrFlags];
    step->length = stepHdr[stepHdrParm];
    bytesLeft -= stepHdrLen;
    *bytesUsed += stepHdrLen;

    // Decode device addr & direction.
    step->devAddr = devAndDir >> 1;
    step->isRead = !!(devAndDir & 1);

    // Decode step flags.
    step->noStart = !!(stepFlags & flagNoStart);

    if (step->isRead)
    {
        // Read could select blockExtra.
        if (stepFlags & flagRecvLen)
        {
            step->blockExtra = req->usePec ? 2 : 1;
        }
    }
    else
    {
        // For write, requested byte count must follow.
        if (bytesLeft < step->length)
        {
            fprintf(stderr, "i2c::parse[%zu] bytesLeft=%zu, parm=%zu?\n",
                    req->numSteps, bytesLeft, step->length);
            return IPMI_CC_REQ_DATA_LEN_INVALID;
        }
        step->reqData = reqBuf + *bytesUsed;
        *bytesUsed += step->length;
    }
    return IPMI_CC_OK;
}

// Parse i2c request.
static ipmi_ret_t parse(const uint8_t* reqBuf, size_t reqLen,
                        i2c::ParsedReq* req)
{
    size_t bytesUsed = 0;
    auto rc = parseReqHdr(reqBuf, reqLen, &bytesUsed, req);
    if (rc != IPMI_CC_OK)
    {
        return rc;
    }
    do
    {
        rc = parseReqStep(reqBuf, reqLen, &bytesUsed, req);
        if (rc != IPMI_CC_OK)
        {
            return rc;
        }
    } while (bytesUsed < reqLen);
    return IPMI_CC_OK;
}

// Convert parsed request to I2C messages.
static ipmi_ret_t buildI2cMsgs(const i2c::ParsedReq& req,
                               std::unique_ptr<i2c::BlockBuf> rxBuf[],
                               struct i2c_msg msgs[],
                               struct i2c_rdwr_ioctl_data* msgset)
{
    size_t minReplyLen = 0;
    for (size_t i = 0; i < req.numSteps; ++msgset->nmsgs, ++i)
    {
        const auto& step = req.step[i];
        auto* msg = &msgs[i];
        msg->addr = step.devAddr;
        if (!step.isRead)
        {
            msg->flags = 0;
            msg->len = step.length;
            msg->buf = const_cast<uint8_t*>(step.reqData);
            continue;
        }
        rxBuf[i] = std::make_unique<i2c::BlockBuf>();
        msg->buf = rxBuf[i]->data();
        if (step.blockExtra == 0)
        {
            msg->flags = I2C_M_RD;
            msg->len = step.length;
            minReplyLen += msg->len;
        }
        else
        {
            // Special buffer setup needed for block read:
            // . 1. msg len must allow for maximum possible transfer,
            // . 2. blockExtra must be preloaded into buf[0]
            // The internal i2c_transfer API is slightly different;
            // the rdwr ioctl handler adapts by moving blockExtra
            // into msg.len where the driver will expect to find it.
            //
            // References:
            //  drivers/i2c/i2c-dev.c: i2cdev_ioctl_rdwr()
            msg->flags = I2C_M_RD | I2C_M_RECV_LEN;
            msg->len = maxRecvLenBuf;
            msg->buf[0] = step.blockExtra;
            minReplyLen += step.blockExtra;
        }
    }
    if (minReplyLen > i2c::largestReply)
    {
        fprintf(stderr, "OemI2c::transfer minReplyLen=%zu?\n", minReplyLen);
        return IPMI_CC_RESPONSE_ERROR; // Won't fit in response message
    }
#ifdef __IPMI_DEBUG__
    for (size_t i = 0; i < req.numSteps; ++i)
    {
        auto* msg = &msgs[i];
        fprintf(stderr, "OemI2c::transfer msg[%zu]: %02x %04x %d\n", i,
                msg->addr, msg->flags, msg->len);
    }
#endif
    return IPMI_CC_OK;
}

static int openBus(BusId localbus)
{
    char busCharDev[16];
    snprintf(busCharDev, sizeof(busCharDev) - 1, "/dev/i2c-%d", localbus);
    int busFd = open(busCharDev, O_RDWR);
    if (busFd < 0)
    {
        fprintf(stderr,
                "NetFn:[0x2E], OEM:[0x002B79], Cmd:[0x02], "
                "I2C Bus Open(\"%s\"): \"%s\"\n",
                busCharDev, strerror(-busFd));
    }
    return busFd;
}

} // namespace i2c

ipmi_ret_t OemI2c::transfer(ipmi_cmd_t cmd, const uint8_t* reqBuf,
                            uint8_t* replyBuf, size_t* dataLen)
{
    // Parse message header.
    auto reqLen = *dataLen;
    *dataLen = 0;
    i2c::ParsedReq req = {};
    auto rc = parse(reqBuf, reqLen, &req);
    if (rc != IPMI_CC_OK)
    {
        return rc;
    }
    // Build full msgset
    std::unique_ptr<i2c::BlockBuf> rxBuf[i2c::maxSteps];
    struct i2c_msg msgs[i2c::maxSteps] = {};
    struct i2c_rdwr_ioctl_data msgset = {
        .msgs = msgs,
        .nmsgs = 0,
    };
    rc = buildI2cMsgs(req, rxBuf, msgs, &msgset);
    if (rc != IPMI_CC_OK)
    {
        return rc;
    }
    // Try to open i2c bus
    int busFd = i2c::openBus(req.localbus);
    if (busFd < 0)
    {
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    int ioError = ioctl(busFd, I2C_RDWR, &msgset);
    // Done with busFd, so close it immediately to avoid leaking it.
    (void)close(busFd);
    if (ioError < 0)
    {
        fprintf(stderr, "OemI2c::transfer I2C_RDWR ioError=%d?\n", ioError);
        return IPMI_CC_UNSPECIFIED_ERROR; // I2C_RDWR I/O error
    }
    // If we read any data, append it, in the order we read it.
    uint8_t* nextReplyByte = replyBuf;
    size_t replyLen = 0;
    for (size_t i = 0; i < req.numSteps; ++i)
    {
        const auto& step = req.step[i];
        if (step.isRead)
        {
            const auto* msg = &msgs[i];
            size_t lenRead =
                step.blockExtra ? *msg->buf + step.blockExtra : msg->len;
            replyLen += lenRead;
            if (replyLen > i2c::largestReply)
            {
                fprintf(stderr, "OemI2c::transfer[%zu] replyLen=%zu?\n", i,
                        replyLen);
                return IPMI_CC_RESPONSE_ERROR; // Won't fit in response message
            }
            memcpy(nextReplyByte, msg->buf, lenRead);
            nextReplyByte += lenRead;
        }
    }
    *dataLen = replyLen;
    return IPMI_CC_OK;
}

void OemI2c::registerWith(Router* oemRouter)
{
    Handler f = [this](ipmi_cmd_t cmd, const uint8_t* reqBuf, uint8_t* replyBuf,
                       size_t* dataLen) {
        return transfer(cmd, reqBuf, replyBuf, dataLen);
    };
    using google::googOemNumber;
    fprintf(stderr, "Registering OEM:[%#08X], Cmd:[%#04X] for I2C\n",
            googOemNumber, i2cCmd);
    oemRouter->registerHandler(googOemNumber, i2cCmd, f);
    fprintf(stderr, "Registering OEM:[%#08X], Cmd:[%#04X] for I2C\n",
            obmcOemNumber, i2cCmd);
    oemRouter->registerHandler(obmcOemNumber, i2cCmd, f);
}

namespace i2c
{
// Currently ipmid dynamically loads providers such as these;
// this creates our singleton upon load.
void setupGlobalOemI2c() __attribute__((constructor));

void setupGlobalOemI2c()
{
    globalOemI2c = std::make_unique<OemI2c>();
    globalOemI2c->registerWith(oem::mutableRouter());
}
} // namespace i2c
} // namespace oem
