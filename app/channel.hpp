#include "nlohmann/json.hpp"

#include <ipmid/api.h>

/** @brief The set channel access IPMI command.
 *
 *  @param[in] netfn
 *  @param[in] cmd
 *  @param[in] request
 *  @param[in,out] response
 *  @param[out] data_len
 *  @param[in] context
 *
 *  @return IPMI_CC_OK on success, non-zero otherwise.
 */
ipmi_ret_t ipmi_set_channel_access(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                   ipmi_request_t request,
                                   ipmi_response_t response,
                                   ipmi_data_len_t data_len,
                                   ipmi_context_t context);

/** @brief The get channel access IPMI command.
 *
 *  @param[in] netfn
 *  @param[in] cmd
 *  @param[in] request
 *  @param[in,out] response
 *  @param[out] data_len
 *  @param[in] context
 *
 *  @return IPMI_CC_OK on success, non-zero otherwise.
 */
ipmi_ret_t ipmi_get_channel_access(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                   ipmi_request_t request,
                                   ipmi_response_t response,
                                   ipmi_data_len_t data_len,
                                   ipmi_context_t context);

/** @brief The get channel info IPMI command.
 *
 *  @param[in] netfn
 *  @param[in] cmd
 *  @param[in] request
 *  @param[in,out] response
 *  @param[out] data_len
 *  @param[in] context
 *
 *  @return IPMI_CC_OK on success, non-zero otherwise.
 */
ipmi_ret_t ipmi_app_channel_info(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                 ipmi_request_t request,
                                 ipmi_response_t response,
                                 ipmi_data_len_t data_len,
                                 ipmi_context_t context);

/** @brief Implementation of get channel cipher suites command
 *
 *  @param[in] netfn - Net Function
 *  @param[in] cmd - Command
 *  @param[in] request - Request pointer
 *  @param[in,out] response - Response pointer
 *  @param[in,out] data_len - Data Length
 *  @param[in] context - Context
 *
 *  @return IPMI_CC_OK on success, non-zero otherwise.
 */
ipmi_ret_t getChannelCipherSuites(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                  ipmi_request_t request,
                                  ipmi_response_t response,
                                  ipmi_data_len_t data_len,
                                  ipmi_context_t context);

namespace cipher
{

static constexpr auto defaultChannelNumber = 1;
static constexpr auto listTypeMask = 0x80;
static constexpr auto listCipherSuite = 0x80;
static constexpr auto listIndexMask = 0x3F;
static constexpr auto respSize = 16;

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

/** @struct GetChannelCipherRequest
 *
 *  IPMI payload for Get Channel Cipher Suites command request
 */
struct GetChannelCipherRequest
{
    uint8_t channelNumber; //!< Channel Number
    uint8_t payloadType;   //!< Payload type number
    uint8_t listIndex;     //!< List Index
} __attribute__((packed));

/** @struct GetChannelCipherRespHeader
 *
 *  IPMI payload for Get Channel Cipher Suites command response header
 */
struct GetChannelCipherRespHeader
{
    uint8_t channelNumber; //!< Channel Number
} __attribute__((packed));
