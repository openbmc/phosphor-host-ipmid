#include "dcmihandler.hpp"
#include "host-ipmid/ipmid-api.h"
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include "utils.hpp"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "xyz/openbmc_project/Common/error.hpp"

using namespace phosphor::logging;
using InternalFailure =
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

void register_netfn_dcmi_functions() __attribute__((constructor));

constexpr auto PCAP_SETTINGS_SERVICE = "xyz.openbmc_project.Settings";
constexpr auto PCAP_PATH    = "/xyz/openbmc_project/control/host0/power_cap";
constexpr auto PCAP_INTERFACE = "xyz.openbmc_project.Control.Power.Cap";

constexpr auto POWER_CAP_PROP = "PowerCap";
constexpr auto POWER_CAP_ENABLE_PROP = "PowerCapEnable";

using namespace phosphor::logging;

uint32_t getPcap(sdbusplus::bus::bus& bus)
{
    auto settingService = ipmi::getService(bus,
                                           PCAP_PATH,PCAP_SETTINGS_SERVICE);

    auto method = bus.new_method_call(settingService.c_str(),
                                      PCAP_PATH,
                                      "org.freedesktop.DBus.Properties",
                                      "Get");

    method.append(PCAP_INTERFACE, POWER_CAP_PROP);
    auto reply = bus.call(method);

    if (reply.is_method_error())
    {
        log<level::ERR>("Error in getPcap prop");
        // TODO openbmc/openbmc#851 - Once available, throw returned error
        // and return IPMI_CC_UNSPECIFIED_ERROR to caller
        return 0;
    }
    sdbusplus::message::variant<uint32_t> pcap;
    reply.read(pcap);

    return sdbusplus::message::variant_ns::get<uint32_t>(pcap);
}

bool getPcapEnabled(sdbusplus::bus::bus& bus)
{
    auto settingService = ipmi::getService(bus,
                                           PCAP_PATH,PCAP_SETTINGS_SERVICE);

    auto method = bus.new_method_call(settingService.c_str(),
                                      PCAP_PATH,
                                      "org.freedesktop.DBus.Properties",
                                      "Get");

    method.append(PCAP_INTERFACE, POWER_CAP_ENABLE_PROP);
    auto reply = bus.call(method);

    if (reply.is_method_error())
    {
        log<level::ERR>("Error in getPcapEnabled prop");
        // TODO openbmc/openbmc#851 - Once available, throw returned error
        // and return IPMI_CC_UNSPECIFIED_ERROR to caller
        return false;
    }
    sdbusplus::message::variant<bool> pcapEnabled;
    reply.read(pcapEnabled);

    return sdbusplus::message::variant_ns::get<bool>(pcapEnabled);
}

ipmi_ret_t ipmi_dcmi_get_power_limit(ipmi_netfn_t netfn, ipmi_cmd_t cmd, 
                              ipmi_request_t request, ipmi_response_t response, 
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    // Default to no power cap enabled
    ipmi_ret_t rc = IPMI_DCMI_CC_NO_ACTIVE_POWER_LIMIT;

    // Get our sdbus object
    sd_bus *bus = ipmid_get_sd_bus_connection();
    sdbusplus::bus::bus sdbus {bus};

    // Read our power cap settings
    auto pcap = getPcap(sdbus);
    auto pcapEnable = getPcapEnabled(sdbus);
    if(pcapEnable)
    {
        // indicate power cap enabled with success return code
        rc = IPMI_CC_OK;
    }

    uint8_t pcapBytes[2] = {0};
    pcapBytes[1] = (pcap & 0xFF00) >> 8;
    pcapBytes[0] = pcap & 0xFF;
    // dcmi-v1-5-rev-spec.pdf 6.6.2.
    uint8_t data_response[] = { 0xDC, 0x00, 0x00, 0x01, pcapBytes[0],
                                pcapBytes[1], 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x01};


    log<level::INFO>("IPMI DCMI POWER CAP INFO",
                     entry("DCMI_PCAP=%u",pcap),
                     entry("DCMI_PCAP_ENABLE=%u",pcapEnable));

    memcpy(response, data_response, sizeof(data_response));
    *data_len = sizeof(data_response);

    return rc;
}

namespace dcmi
{

void readAssetTagObjectTree(dcmi::assettag::ObjectTree& objectTree)
{
    static constexpr auto mapperBusName = "xyz.openbmc_project.ObjectMapper";
    static constexpr auto mapperObjPath = "/xyz/openbmc_project/object_mapper";
    static constexpr auto mapperIface = "xyz.openbmc_project.ObjectMapper";
    static constexpr auto inventoryRoot = "/xyz/openbmc_project/inventory/";

    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    auto depth = 0;

    auto mapperCall = bus.new_method_call(mapperBusName,
                                          mapperObjPath,
                                          mapperIface,
                                          "GetSubTree");

    mapperCall.append(inventoryRoot);
    mapperCall.append(depth);
    mapperCall.append(std::vector<std::string>({dcmi::assetTagIntf}));

    auto mapperReply = bus.call(mapperCall);
    if (mapperReply.is_method_error())
    {
        log<level::ERR>("Error in mapper call");
        elog<InternalFailure>();
    }

    mapperReply.read(objectTree);

    if (objectTree.empty())
    {
        log<level::ERR>("AssetTag property is not populated");
        elog<InternalFailure>();
    }
}

std::string readAssetTag()
{
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    dcmi::assettag::ObjectTree objectTree;

    // Read the object tree with the inventory root to figure out the object
    // that has implemented the Asset tag interface.
    readAssetTagObjectTree(objectTree);

    auto method = bus.new_method_call(
            (objectTree.begin()->second.begin()->first).c_str(),
            (objectTree.begin()->first).c_str(),
            dcmi::propIntf,
            "Get");
    method.append(dcmi::assetTagIntf);
    method.append(dcmi::assetTagProp);

    auto reply = bus.call(method);
    if (reply.is_method_error())
    {
        log<level::ERR>("Error in reading asset tag");
        elog<InternalFailure>();
    }

    sdbusplus::message::variant<std::string> assetTag;
    reply.read(assetTag);

    return assetTag.get<std::string>();
}

void writeAssetTag(const std::string& assetTag)
{
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    dcmi::assettag::ObjectTree objectTree;

    // Read the object tree with the inventory root to figure out the object
    // that has implemented the Asset tag interface.
    readAssetTagObjectTree(objectTree);

    auto method = bus.new_method_call(
            (objectTree.begin()->second.begin()->first).c_str(),
            (objectTree.begin()->first).c_str(),
            dcmi::propIntf,
            "Set");
    method.append(dcmi::assetTagIntf);
    method.append(dcmi::assetTagProp);
    method.append(sdbusplus::message::variant<std::string>(assetTag));

    auto reply = bus.call(method);
    if (reply.is_method_error())
    {
        log<level::ERR>("Error in writing asset tag");
        elog<InternalFailure>();
    }
}

} // namespace dcmi

ipmi_ret_t getAssetTag(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                       ipmi_request_t request, ipmi_response_t response,
                       ipmi_data_len_t data_len, ipmi_context_t context)
{
    auto requestData = reinterpret_cast<const dcmi::GetAssetTagRequest*>
                   (request);
    std::vector<uint8_t> outPayload(sizeof(dcmi::GetAssetTagResponse));
    auto responseData = reinterpret_cast<dcmi::GetAssetTagResponse*>
            (outPayload.data());

    if (requestData->groupID != dcmi::groupExtId)
    {
        *data_len = 0;
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    // Verify offset to read and number of bytes to read are not exceeding the
    // range.
    if ((requestData->offset > dcmi::assetTagMaxOffset) ||
        (requestData->bytes > dcmi::maxBytes) ||
        ((requestData->offset + requestData->bytes) > dcmi::assetTagMaxSize))
    {
        *data_len = 0;
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    std::string assetTag;

    try
    {
        assetTag = dcmi::readAssetTag();
    }
    catch (InternalFailure& e)
    {
        *data_len = 0;
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    responseData->groupID = dcmi::groupExtId;

    // Return if the asset tag is not populated.
    if (!assetTag.size())
    {
        responseData->tagLength = 0;
        memcpy(response, outPayload.data(), outPayload.size());
        *data_len = outPayload.size();
        return IPMI_CC_OK;
    }

    // If the asset tag is longer than 63 bytes, restrict it to 63 bytes to suit
    // Get Asset Tag command.
    if (assetTag.size() > dcmi::assetTagMaxSize)
    {
        assetTag.resize(dcmi::assetTagMaxSize);
    }

    // If the requested offset is beyond the asset tag size.
    if (requestData->offset >= assetTag.size())
    {
        *data_len = 0;
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    auto returnData = assetTag.substr(requestData->offset, requestData->bytes);

    responseData->tagLength = assetTag.size();

    memcpy(response, outPayload.data(), outPayload.size());
    memcpy(static_cast<uint8_t*>(response) + outPayload.size(),
           returnData.data(), returnData.size());
    *data_len = outPayload.size() + returnData.size();

    return IPMI_CC_OK;
}

ipmi_ret_t setAssetTag(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                       ipmi_request_t request, ipmi_response_t response,
                       ipmi_data_len_t data_len, ipmi_context_t context)
{
    auto requestData = reinterpret_cast<const dcmi::SetAssetTagRequest*>
                   (request);
    std::vector<uint8_t> outPayload(sizeof(dcmi::SetAssetTagResponse));
    auto responseData = reinterpret_cast<dcmi::SetAssetTagResponse*>
            (outPayload.data());

    if (requestData->groupID != dcmi::groupExtId)
    {
        *data_len = 0;
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    // Verify offset to read and number of bytes to read are not exceeding the
    // range.
    if ((requestData->offset > dcmi::assetTagMaxOffset) ||
        (requestData->bytes > dcmi::maxBytes) ||
        ((requestData->offset + requestData->bytes) > dcmi::assetTagMaxSize))
    {
        *data_len = 0;
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    std::string assetTag;

    try
    {
        assetTag = dcmi::readAssetTag();

        if (requestData->offset > assetTag.size())
        {
            *data_len = 0;
            return IPMI_CC_PARM_OUT_OF_RANGE;
        }

        assetTag.replace(requestData->offset,
                         assetTag.size() - requestData->offset,
                         static_cast<const char*>(request) +
                         sizeof(dcmi::SetAssetTagRequest),
                         requestData->bytes);

        dcmi::writeAssetTag(assetTag);

        responseData->groupID = dcmi::groupExtId;
        responseData->tagLength = assetTag.size();
        memcpy(response, outPayload.data(), outPayload.size());
        *data_len = outPayload.size();

        return IPMI_CC_OK;
    }
    catch (InternalFailure& e)
    {
        *data_len = 0;
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
}

void register_netfn_dcmi_functions()
{
    // <Get Power Limit>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_GRPEXT, IPMI_CMD_DCMI_GET_POWER);
    ipmi_register_callback(NETFUN_GRPEXT, IPMI_CMD_DCMI_GET_POWER, NULL, ipmi_dcmi_get_power_limit,
                           PRIVILEGE_USER);

    // <Get Asset Tag>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_GRPEXT, IPMI_CMD_DCMI_GET_ASSET_TAG);
    ipmi_register_callback(NETFUN_GRPEXT, IPMI_CMD_DCMI_GET_ASSET_TAG, NULL, getAssetTag,
                           PRIVILEGE_USER);

    // <Set Asset Tag>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_GRPEXT, IPMI_CMD_DCMI_SET_ASSET_TAG);
    ipmi_register_callback(NETFUN_GRPEXT, IPMI_CMD_DCMI_SET_ASSET_TAG, NULL, setAssetTag,
                           PRIVILEGE_OPERATOR);
    return;
}
// 956379
