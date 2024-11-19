#include "serialcmd.hpp"

#include <fmt/format.h>

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/exception.hpp>
#include <sdbusplus/message.hpp>
#include <sdbusplus/slot.hpp>
#include <stdplus/exception.hpp>
#include <stdplus/fd/ops.hpp>
#include <stdplus/print.hpp>

#include <unordered_map>

namespace serialbridge
{

using sdbusplus::bus::bus;
using sdbusplus::message::message;
using sdbusplus::slot::slot;

std::vector<uint8_t> requestBuffer;

bool verbose = false;
uint8_t ctx_state = MSG_IDLE;
uint8_t ctx_escape = 0;

static constexpr uint8_t netFnShift = 2;
static constexpr uint8_t lunMask = (1 << netFnShift) - 1;

/**
 * @brief Table of special characters
 */
std::unordered_map<uint8_t, uint8_t> characters = {
    {BM_START, 0xB0},     /* start */
    {BM_STOP, 0xB5},      /* stop */
    {BM_HANDSHAKE, 0xB6}, /* packet handshake */
    {BM_ESCAPE, 0xBA},    /* data escape */
    {0x1B, 0x3B}          /* escape */
};

/**
 * @brief Calculate IPMI checksum
 */
uint8_t calculateChecksum(uint8_t* data, uint8_t length)
{
    uint8_t checksum = 0;

    // calculate checksum
    for (uint8_t idx = 0; idx < length; idx++)
    {
        checksum += data[idx];
    }

    checksum = (~checksum) + 1;

    // return checksum
    return checksum;
}

/**
 * @brief Return escaped character for the given one
 */
uint8_t getEscapedCharact(uint8_t c)
{
    auto search = characters.find(c);
    if (search == characters.end())
    {
        return c;
    }

    return search->second;
}

/**
 * @brief Return unescaped character for the given one
 */
uint8_t getUnescapedCharact(uint8_t c)
{
    auto search =
        std::find_if(characters.begin(), characters.end(),
                     [c](const auto& map_set) { return map_set.second == c; });

    if (search == characters.end())
    {
        return c;
    }

    return search->first;
}

/**
 * @brief Process IPMI Serial Request State Machine
 */
int consumeIpmiSerialPacket(std::span<uint8_t>& escapedDataBytes,
                            std::vector<uint8_t>& unescapedDataBytes)
{
    for (auto c : escapedDataBytes)
    {
        if (c == BM_START) // START
        {
            ctx_state = MSG_IN_PROGRESS;
            ctx_escape = 0;
        }
        else if (ctx_state != MSG_IN_PROGRESS)
        {
            continue;
        }
        else if (ctx_escape)
        {
            uint8_t unescapedCharact;
            unescapedCharact = getUnescapedCharact(c);

            if (unescapedCharact == c)
            {
                // error, then reset
                ctx_state = MSG_IDLE;
                unescapedDataBytes.clear();
                continue;
            }

            unescapedDataBytes.push_back(unescapedCharact);
            ctx_escape = 0;
        }
        else if (c == BM_ESCAPE)
        {
            ctx_escape = 1;
            continue;
        }
        else if (c == BM_STOP) // STOP
        {
            ctx_state = MSG_IDLE;
            return true;
        }
        else if (c == BM_HANDSHAKE) // Handshake
        {
            unescapedDataBytes.clear();
            continue;
        }
        else if (ctx_state == MSG_IN_PROGRESS)
        {
            unescapedDataBytes.push_back(c);
        }
    }

    return false;
}

/**
 * @brief Encapsluate response to avoid escape character
 */
uint8_t processEscapedCharacter(std::vector<uint8_t>& buffer, uint8_t c)
{
    uint8_t escape = getEscapedCharact(c);
    if (escape != c)
    {
        buffer.push_back(BM_ESCAPE);
    }

    buffer.push_back(escape);

    return c;
}

/**
 * @brief Write function
 */
void write(stdplus::Fd& uart, uint8_t rsAddr, uint8_t rqAddr, uint8_t seq,
           message&& m)
{
    std::vector<uint8_t> buffer;
    std::span<uint8_t> out;
    uint8_t checksum;

    try
    {
        if (m.is_method_error())
        {
            // Extra copy to workaround lack of `const sd_bus_error` constructor
            auto error = *m.get_error();
            throw sdbusplus::exception::SdBusError(&error, "ipmid response");
        }

        std::tuple<uint8_t, uint8_t, uint8_t, uint8_t, std::vector<uint8_t>>
            ret;
        m.read(ret);

        const auto& [netfn, lun, cmd, cc, data] = ret;

        buffer.push_back(BM_START);

        checksum = 0;
        checksum += processEscapedCharacter(buffer, rqAddr);
        checksum += processEscapedCharacter(buffer, (netfn << netFnShift) |
                                                        (lun & lunMask));
        buffer.push_back((~checksum) + 1); // checksum1

        checksum = 0;
        checksum += processEscapedCharacter(buffer, rsAddr);
        checksum += processEscapedCharacter(buffer, (seq << netFnShift) |
                                                        (lun & lunMask));
        checksum += processEscapedCharacter(buffer, cmd);
        checksum += processEscapedCharacter(buffer, cc);

        for (auto c : data)
        {
            checksum += processEscapedCharacter(buffer, c);
        }

        buffer.push_back((~checksum) + 1); // checksum2
        buffer.push_back(BM_STOP);

        out = std::span<uint8_t>(buffer.begin(), buffer.end());

        if (verbose)
        {
            std::string msgToLog =
                "Write serial request message with"
                " len=" +
                std::to_string(buffer.size()) +
                " netfn=" + std::to_string(netfn) +
                " lun=" + std::to_string(lun) + " cmd=" + std::to_string(cmd) +
                " seq=" + std::to_string(seq);
            lg2::info(msgToLog.c_str());

            std::string msgData = "Tx: ";
            for (auto c : buffer)
            {
                msgData += std::format("{:#x} ", c);
            }
            lg2::info(msgData.c_str());
        }
    }
    catch (const std::exception& e)
    {
        fmt::print(stderr, "IPMI Response failure: {}\n", e.what());

        buffer.push_back(1 << 2);
        buffer.push_back(0);
        buffer.push_back(0xff);
        out = std::span<uint8_t>(buffer.begin(), buffer.end());
    }

    stdplus::fd::writeExact(uart, out);
}

/**
 * @brief Read function
 */
void read(stdplus::Fd& uart, bus& bus, slot& outstanding)
{
    std::array<uint8_t, IPMI_SERIAL_MAX_BUFFER_SIZE> buffer;
    auto ipmiSerialPacket = stdplus::fd::read(uart, buffer);

    if (ipmiSerialPacket.empty())
    {
        return;
    }

    if (outstanding)
    {
        fmt::print(stderr, "Canceling outstanding request \n");
        outstanding = slot(nullptr);
    }

    // process ipmi serial packet
    if (!consumeIpmiSerialPacket(ipmiSerialPacket, requestBuffer))
    {
        fmt::print(stderr, "Wait for more data ... \n");
        return;
    }

    // validate ipmi serail packet length
    if (requestBuffer.size() <
        (sizeof(struct IpmiSerialHeader) + IPMI_SERIAL_CHECKSUM_SIZE))
    {
        fmt::print(stderr, "Invalid request length, ignoring \n");
        requestBuffer.clear();
        return;
    }

    // validate checksum1
    if (calculateChecksum(&requestBuffer[0],
                          IPMI_SERIAL_CONNECTION_HEADER_LENGTH))
    {
        fmt::print(stderr, "Invalid request checksum 1 \n");
        requestBuffer.clear();
        return;
    }

    // validate checksum2
    if (calculateChecksum(&requestBuffer[IPMI_SERIAL_CONNECTION_HEADER_LENGTH],
                          requestBuffer.size() -
                              IPMI_SERIAL_CONNECTION_HEADER_LENGTH))
    {
        fmt::print(stderr, "Invalid request checksum 2 \n");
        requestBuffer.clear();
        return;
    }

    auto m = bus.new_method_call("xyz.openbmc_project.Ipmi.Host",
                                 "/xyz/openbmc_project/Ipmi",
                                 "xyz.openbmc_project.Ipmi.Server", "execute");

    std::map<std::string, std::variant<int>> options;
    struct IpmiSerialHeader* header =
        reinterpret_cast<struct IpmiSerialHeader*>(requestBuffer.data());

    uint8_t rsAddr = header->rsAddr;
    uint8_t netfn = header->rsNetFnLUN >> netFnShift;
    uint8_t lun = header->rsNetFnLUN & lunMask;
    uint8_t rqAddr = header->rqAddr;
    uint8_t seq = header->rqSeqLUN >> netFnShift;
    uint8_t cmd = header->cmd;

    std::span req_span{requestBuffer.begin(),
                       requestBuffer.end() -
                           IPMI_SERIAL_CHECKSUM_SIZE}; // remove checksum 2
    m.append(netfn, lun, cmd, req_span.subspan(sizeof(IpmiSerialHeader)),
             options);

    if (verbose)
    {
        std::string msgToLog =
            "Read serial request message with"
            " len=" +
            std::to_string(requestBuffer.size()) +
            " netfn=" + std::to_string(netfn) + " lun=" + std::to_string(lun) +
            " cmd=" + std::to_string(cmd) + " seq=" + std::to_string(seq);
        lg2::info(msgToLog.c_str());

        std::string msgData = "Rx: ";
        for (auto c : requestBuffer)
        {
            msgData += std::format("{:#x} ", c);
        }
        lg2::info(msgData.c_str());
    }

    outstanding = m.call_async(stdplus::exception::ignore(
        [&outstanding, &uart, _rsAddr{rsAddr}, _rqAddr{rqAddr},
         _seq{seq}](message&& m) {
            outstanding = slot(nullptr);
            write(uart, _rsAddr, _rqAddr, _seq, std::move(m));
        }));

    requestBuffer.clear();

    return;
}
/**
 * @brief Set debug verbose
 */
void setVerbose(bool enable)
{
    verbose = enable;
}

} // namespace serialbridge
