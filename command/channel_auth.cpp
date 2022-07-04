#include "channel_auth.hpp"

#include <errno.h>
#include <ipmid/api.h>

#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <nlohmann/json.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <user_channel/channel_layer.hpp>
#include <user_channel/user_layer.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <fstream>
#include <set>
#include <string>

namespace command
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using Json = nlohmann::json;

std::vector<uint8_t>
    GetChannelCapabilities(const std::vector<uint8_t>& inPayload,
                           std::shared_ptr<message::Handler>& /* handler */)
{
    auto request =
        reinterpret_cast<const GetChannelCapabilitiesReq*>(inPayload.data());
    if (inPayload.size() != sizeof(*request))
    {
        std::vector<uint8_t> errorPayload{IPMI_CC_REQ_DATA_LEN_INVALID};
        return errorPayload;
    }
    constexpr unsigned int channelMask = 0x0f;
    uint8_t chNum = ipmi::convertCurrentChannelNum(
        request->channelNumber & channelMask, getInterfaceIndex());

    if (!ipmi::isValidChannel(chNum) ||
        (ipmi::EChannelSessSupported::none ==
         ipmi::getChannelSessionSupport(chNum)) ||
        !ipmi::isValidPrivLimit(request->reqMaxPrivLevel))
    {
        std::vector<uint8_t> errorPayload{IPMI_CC_INVALID_FIELD_REQUEST};
        return errorPayload;
    }

    std::vector<uint8_t> outPayload(sizeof(GetChannelCapabilitiesResp));
    auto response =
        reinterpret_cast<GetChannelCapabilitiesResp*>(outPayload.data());

    // A canned response, since there is no user and channel management.
    response->completionCode = IPMI_CC_OK;

    response->channelNumber = chNum;

    response->ipmiVersion = 1; // IPMI v2.0 extended capabilities available.
    response->reserved1 = 0;
    response->oem = 0;
    response->straightKey = 0;
    response->reserved2 = 0;
    response->md5 = 0;
    response->md2 = 0;

    response->reserved3 = 0;
    response->KGStatus = 0;       // KG is set to default
    response->perMessageAuth = 0; // Per-message Authentication is enabled
    response->userAuth = 0;       // User Level Authentication is enabled
    uint8_t maxChUsers = 0;
    uint8_t enabledUsers = 0;
    uint8_t fixedUsers = 0;
    ipmi::ipmiUserGetAllCounts(maxChUsers, enabledUsers, fixedUsers);

    response->nonNullUsers = enabledUsers > 0 ? 1 : 0; // Non-null usernames
    response->nullUsers = 0;      // Null usernames disabled
    response->anonymousLogin = 0; // Anonymous Login disabled

    response->reserved4 = 0;
    response->extCapabilities = 0x2; // Channel supports IPMI v2.0 connections

    response->oemID[0] = 0;
    response->oemID[1] = 0;
    response->oemID[2] = 0;
    response->oemAuxillary = 0;
    return outPayload;
}

static constexpr const char* configFile =
    "/usr/share/ipmi-providers/cipher_list.json";
static constexpr const char* cipher = "cipher";
static constexpr uint8_t stdCipherSuite = 0xC0;
static constexpr uint8_t oemCipherSuite = 0xC1;
static constexpr const char* oem = "oemiana";
static constexpr const char* auth = "authentication";
static constexpr const char* integrity = "integrity";
static constexpr uint8_t integrityTag = 0x40;
static constexpr const char* conf = "confidentiality";
static constexpr uint8_t confTag = 0x80;

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
static std::pair<std::vector<uint8_t>, std::vector<uint8_t>> getCipherRecords()
{
    std::vector<uint8_t> cipherRecords;
    std::vector<uint8_t> supportedAlgorithmRecords;
    // create set to get the unique supported algorithms
    std::set<uint8_t> supportedAlgorithmSet;

    std::ifstream jsonFile(configFile);
    if (!jsonFile.is_open())
    {
        lg2::error("Channel Cipher suites file not found: {ERROR}", "ERROR",
                   strerror(errno));
        elog<InternalFailure>();
    }

    auto data = Json::parse(jsonFile, nullptr, false);
    if (data.is_discarded())
    {
        lg2::error("Parsing channel cipher suites JSON failed: {ERROR}",
                   "ERROR", strerror(errno));
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

/** @brief this command is used to look up what authentication, integrity,
 *  confidentiality algorithms are supported.
 *
 *  @ param inPayload - vector of input data
 *  @ param handler - pointer to handler
 *
 *  @returns ipmi completion code plus response data
 *   - vector of response data: cc, channel, record data
 **/
std::vector<uint8_t>
    getChannelCipherSuites(const std::vector<uint8_t>& inPayload,
                           std::shared_ptr<message::Handler>& /* handler */)
{
    const auto errorResponse = [](uint8_t cc) {
        std::vector<uint8_t> rsp(1);
        rsp[0] = cc;
        return rsp;
    };

    static constexpr size_t getChannelCipherSuitesReqLen = 3;
    if (inPayload.size() != getChannelCipherSuitesReqLen)
    {
        return errorResponse(IPMI_CC_REQ_DATA_LEN_INVALID);
    }

    static constexpr uint8_t channelMask = 0x0f;
    uint8_t channelNumber = inPayload[0] & channelMask;
    if (channelNumber != inPayload[0])
    {
        return errorResponse(IPMI_CC_INVALID_FIELD_REQUEST);
    }
    static constexpr uint8_t payloadMask = 0x3f;
    uint8_t payloadType = inPayload[1] & payloadMask;
    if (payloadType != inPayload[1])
    {
        return errorResponse(IPMI_CC_INVALID_FIELD_REQUEST);
    }
    static constexpr uint8_t indexMask = 0x3f;
    uint8_t listIndex = inPayload[2] & indexMask;
    static constexpr uint8_t algoSelectShift = 7;
    uint8_t algoSelectBit = inPayload[2] >> algoSelectShift;
    if ((listIndex | (algoSelectBit << algoSelectShift)) != inPayload[2])
    {
        return errorResponse(IPMI_CC_INVALID_FIELD_REQUEST);
    }

    static std::vector<uint8_t> cipherRecords;
    static std::vector<uint8_t> supportedAlgorithms;
    static bool recordInit = false;

    uint8_t rspChannel =
        ipmi::convertCurrentChannelNum(channelNumber, getInterfaceIndex());

    if (!ipmi::isValidChannel(rspChannel))
    {
        return errorResponse(IPMI_CC_INVALID_FIELD_REQUEST);
    }
    if (!ipmi::isValidPayloadType(static_cast<ipmi::PayloadType>(payloadType)))
    {
        lg2::debug("Get channel cipher suites - Invalid payload type: {ERROR}",
                   "ERROR", strerror(errno));
        constexpr uint8_t ccPayloadTypeNotSupported = 0x80;
        return errorResponse(ccPayloadTypeNotSupported);
    }

    if (!recordInit)
    {
        try
        {
            std::tie(cipherRecords, supportedAlgorithms) = getCipherRecords();
            recordInit = true;
        }
        catch (const std::exception& e)
        {
            return errorResponse(IPMI_CC_UNSPECIFIED_ERROR);
        }
    }

    const std::vector<uint8_t>& records =
        algoSelectBit ? cipherRecords : supportedAlgorithms;
    static constexpr auto respSize = 16;

    // Session support is available in active LAN channels.
    if ((ipmi::getChannelSessionSupport(rspChannel) ==
         ipmi::EChannelSessSupported::none) ||
        !(ipmi::doesDeviceExist(rspChannel)))
    {
        lg2::debug("Get channel cipher suites - Device does not exist:{ERROR}",
                   "ERROR", strerror(errno));
        return errorResponse(IPMI_CC_INVALID_FIELD_REQUEST);
    }

    // List index(00h-3Fh), 0h selects the first set of 16, 1h selects the next
    // set of 16 and so on.

    // Calculate the number of record data bytes to be returned.
    auto start =
        std::min(static_cast<size_t>(listIndex) * respSize, records.size());
    auto end = std::min((static_cast<size_t>(listIndex) * respSize) + respSize,
                        records.size());
    auto size = end - start;

    std::vector<uint8_t> rsp;
    rsp.push_back(IPMI_CC_OK);
    rsp.push_back(rspChannel);
    std::copy_n(records.data() + start, size, std::back_inserter(rsp));

    return rsp;
}

} // namespace command
