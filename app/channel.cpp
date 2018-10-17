#include "channel.hpp"

#include "net.hpp"
#include "transporthandler.hpp"
#include "types.hpp"
#include "utils.hpp"

#include <arpa/inet.h>

#include <boost/process/child.hpp>
#include <fstream>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <string>
#include <xyz/openbmc_project/Common/error.hpp>

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

/** @struct GetChannelAccessRequest
 *
 *  IPMI payload for Get Channel access command request.
 */
struct GetChannelAccessRequest
{
    uint8_t channelNumber;   //!< Channel number.
    uint8_t volatileSetting; //!< Get non-volatile or the volatile setting.
} __attribute__((packed));

/** @struct GetChannelAccessResponse
 *
 *  IPMI payload for Get Channel access command response.
 */
struct GetChannelAccessResponse
{
    uint8_t settings;       //!< Channel settings.
    uint8_t privilegeLimit; //!< Channel privilege level limit.
} __attribute__((packed));

ipmi_ret_t ipmi_get_channel_access(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                   ipmi_request_t request,
                                   ipmi_response_t response,
                                   ipmi_data_len_t data_len,
                                   ipmi_context_t context)
{
    auto requestData =
        reinterpret_cast<const GetChannelAccessRequest*>(request);
    std::vector<uint8_t> outPayload(sizeof(GetChannelAccessResponse));
    auto responseData =
        reinterpret_cast<GetChannelAccessResponse*>(outPayload.data());

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
    // Defaulting the channel privilege to administrator level.
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
                                 ipmi_request_t request,
                                 ipmi_response_t response,
                                 ipmi_data_len_t data_len,
                                 ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    uint8_t resp[] = {1,
                      IPMI_CHANNEL_MEDIUM_TYPE_OTHER,
                      IPMI_CHANNEL_TYPE_IPMB,
                      1,
                      0x41,
                      0xA7,
                      0x00,
                      0,
                      0};
    uint8_t* p = (uint8_t*)request;
    int channel = (*p) & CHANNEL_MASK;
    std::string ethdevice = ipmi::network::ChanneltoEthernet(channel);

    // The supported channels numbers are those which are configured.
    // Channel Number E is used as way to identify the current channel
    // that the command is being is received from.
    if (channel != 0xe && ethdevice.empty())
    {
        rc = IPMI_CC_PARM_OUT_OF_RANGE;
        *data_len = 0;
    }
    else
    {
        *data_len = sizeof(resp);
        memcpy(response, resp, *data_len);
    }

    return rc;
}

namespace cipher
{

/** @brief Get the supported Cipher records
 *
 * The cipher records are read from the JSON file and converted into cipher
 * suite record format mentioned in the IPMI specification. The records can be
 * either OEM or standard cipher. Each json entry is parsed and converted into
 * the cipher record format and pushed into the vector.
 *
 * @return vector containing all the cipher suite records.
 *
 */
std::vector<uint8_t> getCipherRecords()
{
    std::vector<uint8_t> records;

    std::ifstream jsonFile(configFile);
    if (!jsonFile.is_open())
    {
        log<level::ERR>("Channel Cipher suites file not found");
        elog<InternalFailure>();
    }

    auto data = Json::parse(jsonFile, nullptr, false);
    if (data.is_discarded())
    {
        log<level::ERR>("Parsing channel cipher suites JSON failed");
        elog<InternalFailure>();
    }

    for (const auto& record : data)
    {
        if (record.find(oem) != record.end())
        {
            // OEM cipher suite - 0xC1
            records.push_back(oemCipherSuite);
            // Cipher Suite ID
            records.push_back(record.value(cipher, 0));
            // OEM IANA - 3 bytes
            records.push_back(record.value(oem, 0));
            records.push_back(record.value(oem, 0) >> 8);
            records.push_back(record.value(oem, 0) >> 16);
        }
        else
        {
            // OEM cipher suite - 0xC0
            records.push_back(stdCipherSuite);
            // Cipher Suite ID
            records.push_back(record.value(cipher, 0));
        }

        // Authentication algorithm number
        records.push_back(record.value(auth, 0));
        // Integrity algorithm number
        records.push_back(record.value(integrity, 0) | integrityTag);
        // Confidentiality algorithm number
        records.push_back(record.value(conf, 0) | confTag);
    }

    return records;
}

} // namespace cipher

ipmi_ret_t getChannelCipherSuites(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                  ipmi_request_t request,
                                  ipmi_response_t response,
                                  ipmi_data_len_t data_len,
                                  ipmi_context_t context)
{
    static std::vector<uint8_t> records;
    static auto recordInit = false;

    auto requestData =
        reinterpret_cast<const GetChannelCipherRequest*>(request);

    if (*data_len < sizeof(GetChannelCipherRequest))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *data_len = 0;

    // Support only for list algorithms by cipher suite
    if (cipher::listCipherSuite !=
        (requestData->listIndex & cipher::listTypeMask))
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    if (!recordInit)
    {
        try
        {
            records = cipher::getCipherRecords();
            recordInit = true;
        }
        catch (const std::exception& e)
        {
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
    }

    // List index(00h-3Fh), 0h selects the first set of 16, 1h selects the next
    // set of 16 and so on.
    auto index =
        static_cast<size_t>(requestData->listIndex & cipher::listIndexMask);

    // Calculate the number of record data bytes to be returned.
    auto start = std::min(index * cipher::respSize, records.size());
    auto end =
        std::min((index * cipher::respSize) + cipher::respSize, records.size());
    auto size = end - start;

    auto responseData = reinterpret_cast<GetChannelCipherRespHeader*>(response);
    responseData->channelNumber = cipher::defaultChannelNumber;

    if (!size)
    {
        *data_len = sizeof(GetChannelCipherRespHeader);
    }
    else
    {
        std::copy_n(records.data() + start, size,
                    static_cast<uint8_t*>(response) + 1);
        *data_len = size + sizeof(GetChannelCipherRespHeader);
    }

    return IPMI_CC_OK;
}

template <typename... ArgTypes>
static int executeCmd(const char* path, ArgTypes&&... tArgs)
{
    boost::process::child execProg(path, const_cast<char*>(tArgs)...);
    execProg.wait();
    return execProg.exit_code();
}

/** @brief Enable the network IPMI service on the specified ethernet interface.
 *
 *  @param[in] intf - ethernet interface on which to enable IPMI
 */
void enableNetworkIPMI(const std::string& intf)
{
    // Check if there is a iptable filter to drop IPMI packets for the
    // interface.
    auto retCode =
        executeCmd("/usr/sbin/iptables", "-C", "INPUT", "-p", "udp", "-i",
                   intf.c_str(), "--dport", "623", "-j", "DROP");

    // If the iptable filter exists, delete the filter.
    if (!retCode)
    {
        auto response =
            executeCmd("/usr/sbin/iptables", "-D", "INPUT", "-p", "udp", "-i",
                       intf.c_str(), "--dport", "623", "-j", "DROP");
        if (response)
        {
            log<level::ERR>("Dropping the iptables filter failed",
                            entry("INTF=%s", intf.c_str()),
                            entry("RETURN_CODE=%d", response));
            return;
        }

        response =
            std::system("/usr/sbin/iptables-save > /var/lib/iptables_rules");
        if (response)
        {
            log<level::ERR>("Persisting the iptables failed",
                            entry("INTF=%s", intf.c_str()),
                            entry("RETURN_CODE=%d", response));
        }
    }
}

/** @brief Disable the network IPMI service on the specified ethernet interface.
 *
 *  @param[in] intf - ethernet interface on which to disable IPMI
 */
void disableNetworkIPMI(const std::string& intf)
{
    // Check if there is a iptable filter to drop IPMI packets for the
    // interface.
    auto retCode =
        executeCmd("/usr/sbin/iptables", "-C", "INPUT", "-p", "udp", "-i",
                   intf.c_str(), "--dport", "623", "-j", "DROP");

    // If the iptable filter does not exist, add filter to drop network IPMI
    // packets
    if (retCode)
    {
        auto response =
            executeCmd("/usr/sbin/iptables", "-I", "INPUT", "-p", "udp", "-i",
                       intf.c_str(), "--dport", "623", "-j", "DROP");
        if (response)
        {
            log<level::ERR>("Inserting iptables filter failed",
                            entry("INTF=%s", intf.c_str()),
                            entry("RETURN_CODE=%d", response));
            return;
        }

        response =
            std::system("/usr/sbin/iptables-save > /var/lib/iptables_rules");
        if (response)
        {
            log<level::ERR>("Persisting the iptables failed",
                            entry("INTF=%s", intf.c_str()),
                            entry("RETURN_CODE=%d", response));
        }
    }
}

/** @struct SetChannelAccessRequest
 *
 *  IPMI payload for Set Channel access command request.
 */
struct SetChannelAccessRequest
{
    uint8_t channelNumber; //!< Channel number
    uint8_t accessMode;    //!< Access mode for IPMI messaging
    uint8_t privLevel;     //!< Channel Privilege Level
} __attribute__((packed));

ipmi_ret_t ipmi_set_channel_access(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                   ipmi_request_t request,
                                   ipmi_response_t response,
                                   ipmi_data_len_t data_len,
                                   ipmi_context_t context)
{
    auto requestData =
        reinterpret_cast<const SetChannelAccessRequest*>(request);

    int channel = requestData->channelNumber;
    // Validate the channel number corresponds to any of the network channel.
    auto ethdevice = ipmi::network::ChanneltoEthernet(channel);
    if (ethdevice.empty())
    {
        *data_len = 0;
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    // Bits[2:0] indicates the Access Mode, this mask field will extract the
    // access mode from the command data.
    static constexpr auto accessModeMask = 0x07;
    auto accessMode = requestData->accessMode & accessModeMask;
    static constexpr auto disabled = 0;
    static constexpr auto enabled = 2;

    try
    {
        if (accessMode == enabled)
        {
            enableNetworkIPMI(ethdevice);
        }
        else if (accessMode == disabled)
        {
            disableNetworkIPMI(ethdevice);
        }
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        log<level::ERR>(e.what());
        *data_len = 0;
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    return IPMI_CC_OK;
}
