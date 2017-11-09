#include "channel.hpp"
#include "types.hpp"
#include "transporthandler.hpp"
#include "utils.hpp"
#include "net.hpp"

#include <string>
#include <arpa/inet.h>

#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include "xyz/openbmc_project/Common/error.hpp"


using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

/** @struct GetChannelAccessRequest
 *
 *  IPMI payload for Get Channel access command request.
 */
struct GetChannelAccessRequest
{
    uint8_t channelNumber;      //!< Channel number.
    uint8_t volatileSetting;    //!< Get non-volatile or the volatile setting.
} __attribute__((packed));

/** @struct GetChannelAccessResponse
 *
 *  IPMI payload for Get Channel access command response.
 */
struct GetChannelAccessResponse
{
    uint8_t settings;          //!< Channel settings.
    uint8_t privilegeLimit;    //!< Channel privilege level limit.
} __attribute__((packed));


ipmi_ret_t ipmi_get_channel_access(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                            ipmi_request_t request, ipmi_response_t response,
                            ipmi_data_len_t data_len, ipmi_context_t context)
{
    auto requestData = reinterpret_cast<const GetChannelAccessRequest*>
                   (request);
    std::vector<uint8_t> outPayload(sizeof(GetChannelAccessResponse));
    auto responseData = reinterpret_cast<GetChannelAccessResponse*>
            (outPayload.data());

    /*
     * The value Eh is used as a way to identify the current channel that
     * the command is being received from.
     */
    constexpr auto channelE = 0x0E;
    int channel = requestData->channelNumber;
    auto ethdevice = ipmi::network::ChanneltoEthernet(channel);

    if (channel != channelE && ethdevice.empty())
    {
        *data_len = 0;
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    /*
     * [7:6] - reserved
     * [5]   - 1b = Alerting disabled
     * [4]   - 1b = per message authentication disabled
     * [3]   - 0b = User level authentication enabled
     * [2:0] - 2h = always available
     */
    constexpr auto channelSetting = 0x32;

    responseData->settings = channelSetting;
    //Defaulting the channel privilege to administrator level.
    responseData->privilegeLimit = PRIVILEGE_ADMIN;

    *data_len = outPayload.size();
    memcpy(response, outPayload.data(), *data_len);

    return IPMI_CC_OK;
}

// ATTENTION: This ipmi function is very hardcoded on purpose
// OpenBMC does not fully support IPMI.  This command is useful
// to have around because it enables testing of interfaces with
// the IPMI tool.
#define GET_CHANNEL_INFO_CHANNEL_OFFSET 0
// IPMI Table 6-2
#define IPMI_CHANNEL_TYPE_IPMB 1
// IPMI Table 6-3
#define IPMI_CHANNEL_MEDIUM_TYPE_OTHER 6

ipmi_ret_t ipmi_app_channel_info(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    uint8_t resp[] = {
        1,
        IPMI_CHANNEL_MEDIUM_TYPE_OTHER,
        IPMI_CHANNEL_TYPE_IPMB,
        1,0x41,0xA7,0x00,0,0};
    uint8_t *p = (uint8_t*) request;
    int channel = (*p) & CHANNEL_MASK;
    std::string ethdevice = ipmi::network::ChanneltoEthernet(channel);

    // The supported channels numbers are those which are configured.
    // Channel Number E is used as way to identify the current channel
    // that the command is being is received from.
    if (channel != 0xe && ethdevice.empty()) {
        rc = IPMI_CC_PARM_OUT_OF_RANGE;
        *data_len = 0;
    } else {
        *data_len = sizeof(resp);
        memcpy(response, resp, *data_len);
    }

    return rc;
}
