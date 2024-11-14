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
static const std::unordered_map<uint8_t, uint8_t> characters = {
    {bmStart, 0xB0},     /* start */
    {bmStop, 0xB5},      /* stop */
    {bmHandshake, 0xB6}, /* packet handshake */
    {bmEscape, 0xBA},    /* data escape */
    {0x1B, 0x3B}         /* escape */
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
uint8_t SerialChannel::getUnescapedCharacter(uint8_t c)
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
        if (c == bmStart) // START
        {
            msgState = MsgState::msgInProgress;
        }
        else if (msgState == MsgState::msgIdle)
        {
            continue;
        }
        else if (msgState == MsgState::msgInEscape)
        {
            uint8_t unescapedCharacter;
            unescapedCharacter = getUnescapedCharacter(c);

            if (unescapedCharacter == c)
            {
                // error, then reset
                msgState = MsgState::msgIdle;
                unescapedDataBytes.clear();
                continue;
            }

            unescapedDataBytes.push_back(unescapedCharacter);
            msgState = MsgState::msgInProgress;
        }
        else if (c == bmEscape)
        {
            msgState = MsgState::msgInEscape;
            continue;
        }
        else if (c == bmStop) // STOP
        {
            msgState = MsgState::msgIdle;
            return true;
        }
        else if (c == bmHandshake) // Handshake
        {
            unescapedDataBytes.clear();
            continue;
        }
        else if (msgState == MsgState::msgInProgress)
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
                                  buffer.push_back(bmEscape);
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
int SerialChannel::write(stdplus::Fd& uart, uint8_t rsAddr, uint8_t rqAddr,
                         uint8_t seq, sdbusplus::message_t&& m)
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

        uint8_t netFn = 0xff;
        uint8_t lun = 0xff;
        uint8_t cmd = 0xff;
        uint8_t cc = 0xff;
        std::vector<uint8_t> data;

        m.read(std::tie(netFn, lun, cmd, cc, data));

        uint8_t netFnLun = (netFn << netFnShift) | (lun & lunMask);
        uint8_t seqLun = (seq << netFnShift) | (lun & lunMask);

        std::vector<uint8_t> connectionHeader = {rqAddr, netFnLun};
        std::vector<uint8_t> messageHeader = {rsAddr, seqLun, cmd, cc};

        // Reserve the buffer size to avoid relloc and copy
        responseBuffer.clear();
        responseBuffer.reserve(
            sizeof(struct IpmiSerialHeader) + 2 * data.size() +
            4); // 4 for bmStart & bmStop & 2 checksums

        // bmStart
        responseBuffer.push_back(bmStart);

        // Assemble connection header and checksum
        checksum = processEscapedCharacter(responseBuffer, connectionHeader);
        responseBuffer.push_back(-checksum); // checksum1

        // Assemble response message and checksum
        checksum = processEscapedCharacter(responseBuffer, messageHeader);
        checksum +=
            processEscapedCharacter(responseBuffer, std::vector<uint8_t>(data));
        responseBuffer.push_back(-checksum); // checksum2

        // bmStop
        responseBuffer.push_back(bmStop);

        out = std::span<uint8_t>(responseBuffer.begin(), responseBuffer.end());

        if (verbose)
        {
            lg2::info(
                "Write serial request message with len={LEN}, netfn={NETFN}, "
                "lun={LUN}, cmd={CMD}, seq={SEQ}",
                "LEN", responseBuffer.size(), "NETFN", netFn, "LUN", lun, "CMD",
                cmd, "SEQ", seq);

            std::string msgData = "Tx: ";
            for (auto c : responseBuffer)
            {
                msgData += std::format("{:#x} ", c);
            }
            lg2::info(msgData.c_str());
        }

        stdplus::fd::writeExact(uart, out);
    }
    catch (const std::exception& e)
    {
        lg2::error("IPMI Response failure: {MSG}", "MSG", e);

        return -1;
    }

    return out.size();
}

/**
 * @brief Read function
 */
void SerialChannel::read(stdplus::Fd& uart, sdbusplus::bus_t& bus,
                         sdbusplus::slot_t& outstanding)
{
    std::array<uint8_t, ipmiSerialMaxBufferSize> buffer;
    auto ipmiSerialPacket = stdplus::fd::read(uart, buffer);

    if (ipmiSerialPacket.empty())
    {
        return;
    }

    if (outstanding)
    {
        lg2::error("Canceling outstanding request \n");
        outstanding = sdbusplus::slot_t(nullptr);
    }

    // process ipmi serial packet
    if (!consumeIpmiSerialPacket(ipmiSerialPacket, requestBuffer))
    {
        lg2::info("Wait for more data ... \n");
        return;
    }

    // validate ipmi serial packet length
    if (requestBuffer.size() <
        (sizeof(struct IpmiSerialHeader) + ipmiSerialChecksumSize))
    {
        lg2::error("Invalid request length, ignoring \n");
        requestBuffer.clear();
        return;
    }

    // validate checksum1
    if (calculateChecksum(std::span<uint8_t>(requestBuffer.begin(),
                                             ipmiSerialConnectionHeaderLength)))
    {
        lg2::error("Invalid request checksum 1 \n");
        requestBuffer.clear();
        return;
    }

    // validate checksum2
    if (calculateChecksum(std::span<uint8_t>(
            &requestBuffer[ipmiSerialConnectionHeaderLength],
            requestBuffer.size() - ipmiSerialConnectionHeaderLength)))
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
    uint8_t netFn = header->rsNetFnLUN >> netFnShift;
    uint8_t lun = header->rsNetFnLUN & lunMask;
    uint8_t rqAddr = header->rqAddr;
    uint8_t seq = header->rqSeqLUN >> netFnShift;
    uint8_t cmd = header->cmd;

    std::span reqSpan{requestBuffer.begin(),
                      requestBuffer.end() -
                          ipmiSerialChecksumSize}; // remove checksum 2
    m.append(netFn, lun, cmd, reqSpan.subspan(sizeof(IpmiSerialHeader)),
             options);

    if (verbose)
    {
        lg2::info("Read serial request message with len={LEN}, netFn={NETFN}, "
                  "lun={LUN}, cmd={CMD}, seq={SEQ}",
                  "LEN", requestBuffer.size(), "NETFN", netFn, "LUN", lun,
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
         _seq{seq}](sdbusplus::message_t&& m) {
            outstanding = sdbusplus::slot_t(nullptr);

            if (write(uart, _rsAddr, _rqAddr, _seq, std::move(m)) < 0)
            {
                lg2::error(
                    "Occur an error while attempting to send the response.");
            }
        }));

    requestBuffer.clear();

    return;
}

} // namespace serialbridge
