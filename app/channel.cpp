#include "channel.hpp"

#include "transporthandler.hpp"
#include "user_channel/channel_layer.hpp"

#include <arpa/inet.h>

#include <boost/process/child.hpp>
#include <fstream>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <set>
#include <string>
#include <xyz/openbmc_project/Common/error.hpp>

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

namespace cipher
{

/** @brief Get the supported Cipher records
 *
 * The cipher records are read from the JSON file and converted into
 * 1. cipher suite record format mentioned in the IPMI specification. The
 * records can be either OEM or standard cipher. Each json entry is parsed and
 * converted into the cipher record format and pushed into the vector.
 * 2. Algorithms listed in vector format
 *
 * @return pair of vector containing 1. all the cipher suite records. 2.
 * Algorithms supported
 *
 */
std::pair<std::vector<uint8_t>, std::vector<uint8_t>> getCipherRecords()
{
    std::vector<uint8_t> cipherRecords;
    std::vector<uint8_t> supportedAlgorithmRecords;
    // create set to get the unique supported algorithms
    std::set<uint8_t> supportedAlgorithmSet;

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
            cipherRecords.push_back(oemCipherSuite);
            // Cipher Suite ID
            cipherRecords.push_back(record.value(cipher, 0));
            // OEM IANA - 3 bytes
            cipherRecords.push_back(record.value(oem, 0));
            cipherRecords.push_back(record.value(oem, 0) >> 8);
            cipherRecords.push_back(record.value(oem, 0) >> 16);
        }
        else
        {
            // Standard cipher suite - 0xC0
            cipherRecords.push_back(stdCipherSuite);
            // Cipher Suite ID
            cipherRecords.push_back(record.value(cipher, 0));
        }

        // Authentication algorithm number
        cipherRecords.push_back(record.value(auth, 0));
        supportedAlgorithmSet.insert(record.value(auth, 0));

        // Integrity algorithm number
        cipherRecords.push_back(record.value(integrity, 0) | integrityTag);
        supportedAlgorithmSet.insert(record.value(integrity, 0) | integrityTag);

        // Confidentiality algorithm number
        cipherRecords.push_back(record.value(conf, 0) | confTag);
        supportedAlgorithmSet.insert(record.value(conf, 0) | confTag);
    }

    // copy the set to supportedAlgorithmRecord which is vector based.
    std::copy(supportedAlgorithmSet.begin(), supportedAlgorithmSet.end(),
              std::back_inserter(supportedAlgorithmRecords));

    return std::make_pair(cipherRecords, supportedAlgorithmRecords);
}

} // namespace cipher

ipmi_ret_t getChannelCipherSuites(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                  ipmi_request_t request,
                                  ipmi_response_t response,
                                  ipmi_data_len_t data_len,
                                  ipmi_context_t context)
{
    static std::vector<uint8_t> cipherRecords;
    static std::vector<uint8_t> supportedAlgorithms;
    static auto recordInit = false;

    auto requestData =
        reinterpret_cast<const GetChannelCipherRequest*>(request);

    if (*data_len < sizeof(GetChannelCipherRequest))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *data_len = 0;

    if (!recordInit)
    {
        try
        {
            std::tie(cipherRecords, supportedAlgorithms) =
                cipher::getCipherRecords();
            recordInit = true;
        }
        catch (const std::exception& e)
        {
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
    }

    const auto& records = (cipher::listCipherSuite ==
                           (requestData->listIndex & cipher::listTypeMask))
                              ? cipherRecords
                              : supportedAlgorithms;

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
                            entry("RETURN_CODE:%d", response));
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
                            entry("RETURN_CODE:%d", response));
        }
    }
}
