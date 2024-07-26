#include "nlohmann/json.hpp"

#include <ipmid/api.hpp>

/** @brief this command is used to look up what authentication, integrity,
 *  confidentiality algorithms are supported.
 *
 *  @ param ctx - context pointer
 *  @ param channelNumber - channel number
 *  @ param payloadType - payload type
 *  @ param listIndex - list index
 *  @ param algoSelectBit - list algorithms
 *
 *  @returns ipmi completion code plus response data
 *  - rspChannel - channel number for authentication algorithm.
 *  - rspRecords - cipher suite records.
 **/
ipmi::RspType<uint8_t,             // Channel Number
              std::vector<uint8_t> // Cipher Records
              >
    getChannelCipherSuites(ipmi::Context::ptr ctx, uint4_t channelNumber,
                           uint4_t reserved1, uint8_t payloadType,
                           uint6_t listIndex, uint1_t reserved2,
                           uint1_t algoSelectBit);

namespace cipher
{

static constexpr auto listCipherSuite = 0x80;

using Json = nlohmann::json;
static constexpr auto configFile = "/usr/share/ipmi-providers/cipher_list.json";
static constexpr auto cipher = "cipher";
static constexpr auto stdCipherSuite = 0xC0;
static constexpr auto oemCipherSuite = 0xC1;
static constexpr auto oem = "oemiana";
static constexpr auto auth = "authentication";
static constexpr auto integrity = "integrity";
static constexpr auto integrityTag = 0x40;
static constexpr auto conf = "confidentiality";
static constexpr auto confTag = 0x80;

} // namespace cipher
