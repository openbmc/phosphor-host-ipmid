#include "serialcmd.hpp"

#include <fmt/format.h>

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/exception.hpp>
#include <sdbusplus/message.hpp>
#include <sdbusplus/slot.hpp>
#include <stdplus/exception.hpp>
#include <stdplus/fd/ops.hpp>

#include <numeric>
#include <ranges>
#include <unordered_map>

namespace serialbridge
{

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
uint8_t SerialChannel::calculateChecksum(std::span<uint8_t> data)
{
    uint8_t checksum;

    checksum = std::accumulate(data.begin(), data.end(), 0);
    checksum = (~checksum) + 1;

    // return checksum
    return checksum;
}

/**
 * @brief Return unescaped character for the given one
 */
uint8_t SerialChannel::getUnescapedCharact(uint8_t c)
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
int SerialChannel::consumeIpmiSerialPacket(
    std::span<uint8_t>& escapedDataBytes,
    std::vector<uint8_t>& unescapedDataBytes)
{
    unescapedDataBytes.reserve(escapedDataBytes.size());

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
uint8_t SerialChannel::processEscapedCharacter(std::vector<uint8_t>& buffer,
                                               const std::vector<uint8_t>& data)
{
    uint8_t checksum = 0;

    std::ranges::for_each(data.begin(), data.end(),
                          [&buffer, &checksum](const auto& c) {
                              auto search = characters.find(c);
                              if (search != characters.end())
                              {
                                  buffer.push_back(BM_ESCAPE);
                                  buffer.push_back(search->second);
                              }
                              else
                              {
                                  buffer.push_back(c);
                              }

                              checksum += c;
                          });

    return checksum;
}

/**
 * @brief Write function
 */
void SerialChannel::write(stdplus::Fd& uart, uint8_t rsAddr, uint8_t rqAddr,
                          uint8_t seq, message&& m)
{
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

        uint8_t netFnLun = (netfn << netFnShift) | (lun & lunMask);
        uint8_t seqLun = (seq << netFnShift) | (lun & lunMask);

        std::vector<uint8_t> connectionHeader = {rqAddr, netFnLun};
        std::vector<uint8_t> messageHeader = {rsAddr, seqLun, cmd, cc};

        // Reserve the buffer size to avoid relloc and copy
        responseBuffer.reserve(sizeof(struct IpmiSerialHeader) +
                               2 * data.size() + 2); // 2 for BM_START & BM_STOP

        // BM_START
        responseBuffer.push_back(BM_START);

        // Assemble connection header and checksum
        checksum = processEscapedCharacter(responseBuffer, connectionHeader);
        responseBuffer.push_back(-checksum); // checksum1

        // Assemble response message and checksum
        checksum = processEscapedCharacter(responseBuffer, messageHeader);
        checksum +=
            processEscapedCharacter(responseBuffer, std::vector<uint8_t>(data));
        responseBuffer.push_back(-checksum); // checksum2

        // BM_STOP
        responseBuffer.push_back(BM_STOP);

        out = std::span<uint8_t>(responseBuffer.begin(), responseBuffer.end());

        if (verbose)
        {
            lg2::info(
                "Write serial request message with len={LEN}, netfn={NETFN}, "
                "lun={LUN}, cmd={CMD}, seq={SEQ}",
                "LEN", responseBuffer.size(), "NETFN", netfn, "LUN", lun, "CMD",
                cmd, "SEQ", seq);

            std::string msgData = "Tx: ";
            for (auto c : responseBuffer)
            {
                msgData += std::format("{:#x} ", c);
            }
            lg2::info(msgData.c_str());
        }
    }
    catch (const std::exception& e)
    {
        lg2::error("IPMI Response failure: {MSG}", "MSG", e.what());

        responseBuffer.push_back(1 << 2);
        responseBuffer.push_back(0);
        responseBuffer.push_back(0xff);
        out = std::span<uint8_t>(responseBuffer.begin(), responseBuffer.end());
    }

    stdplus::fd::writeExact(uart, out);

    responseBuffer.clear();
}

/**
 * @brief Read function
 */
void SerialChannel::read(stdplus::Fd& uart, bus& bus, slot& outstanding)
{
    std::array<uint8_t, IPMI_SERIAL_MAX_BUFFER_SIZE> buffer;
    auto ipmiSerialPacket = stdplus::fd::read(uart, buffer);

    if (ipmiSerialPacket.empty())
    {
        return;
    }

    if (outstanding)
    {
        lg2::error("Canceling outstanding request \n");
        outstanding = slot(nullptr);
    }

    // process ipmi serial packet
    if (!consumeIpmiSerialPacket(ipmiSerialPacket, requestBuffer))
    {
        lg2::info("Wait for more data ... \n");
        return;
    }

    // validate ipmi serial packet length
    if (requestBuffer.size() <
        (sizeof(struct IpmiSerialHeader) + IPMI_SERIAL_CHECKSUM_SIZE))
    {
        lg2::error("Invalid request length, ignoring \n");
        requestBuffer.clear();
        return;
    }

    // validate checksum1
    if (calculateChecksum(std::span<uint8_t>(
            requestBuffer.begin(), IPMI_SERIAL_CONNECTION_HEADER_LENGTH)))
    {
        lg2::error("Invalid request checksum 1 \n");
        requestBuffer.clear();
        return;
    }

    // validate checksum2
    if (calculateChecksum(std::span<uint8_t>(
            &requestBuffer[IPMI_SERIAL_CONNECTION_HEADER_LENGTH],
            requestBuffer.size() - IPMI_SERIAL_CONNECTION_HEADER_LENGTH)))
    {
        lg2::error("Invalid request checksum 2 \n");
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
        lg2::info("Read serial request message with len={LEN}, netfn={NETFN}, "
                  "lun={LUN}, cmd={CMD}, seq={SEQ}",
                  "LEN", requestBuffer.size(), "NETFN", netfn, "LUN", lun,
                  "CMD", cmd, "SEQ", seq);

        std::string msgData = "Rx: ";
        for (auto c : requestBuffer)
        {
            msgData += std::format("{:#x} ", c);
        }
        lg2::info(msgData.c_str());
    }

    outstanding = m.call_async(stdplus::exception::ignore(
        [&outstanding, this, &uart, _rsAddr{rsAddr}, _rqAddr{rqAddr},
         _seq{seq}](message&& m) {
            outstanding = slot(nullptr);
            write(uart, _rsAddr, _rqAddr, _seq, std::move(m));
        }));

    requestBuffer.clear();

    return;
}

} // namespace serialbridge
