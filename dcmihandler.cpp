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

constexpr auto PCAP_PATH    = "/xyz/openbmc_project/control/host0/power_cap";
constexpr auto PCAP_INTERFACE = "xyz.openbmc_project.Control.Power.Cap";

constexpr auto POWER_CAP_PROP = "PowerCap";
constexpr auto POWER_CAP_ENABLE_PROP = "PowerCapEnable";

using namespace phosphor::logging;

namespace dcmi
{

uint32_t getPcap(sdbusplus::bus::bus& bus)
{
    auto settingService = ipmi::getService(bus,
                                           PCAP_INTERFACE,PCAP_PATH);

    auto method = bus.new_method_call(settingService.c_str(),
                                      PCAP_PATH,
                                      "org.freedesktop.DBus.Properties",
                                      "Get");

    method.append(PCAP_INTERFACE, POWER_CAP_PROP);
    auto reply = bus.call(method);

    if (reply.is_method_error())
    {
        log<level::ERR>("Error in getPcap prop");
        elog<InternalFailure>();
    }
    sdbusplus::message::variant<uint32_t> pcap;
    reply.read(pcap);

    return pcap.get<uint32_t>();
}

bool getPcapEnabled(sdbusplus::bus::bus& bus)
{
    auto settingService = ipmi::getService(bus,
                                           PCAP_INTERFACE,PCAP_PATH);

    auto method = bus.new_method_call(settingService.c_str(),
                                      PCAP_PATH,
                                      "org.freedesktop.DBus.Properties",
                                      "Get");

    method.append(PCAP_INTERFACE, POWER_CAP_ENABLE_PROP);
    auto reply = bus.call(method);

    if (reply.is_method_error())
    {
        log<level::ERR>("Error in getPcapEnabled prop");
        elog<InternalFailure>();
    }
    sdbusplus::message::variant<bool> pcapEnabled;
    reply.read(pcapEnabled);

    return pcapEnabled.get<bool>();
}

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

ipmi_ret_t getPowerLimit(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                         ipmi_request_t request, ipmi_response_t response,
                         ipmi_data_len_t data_len, ipmi_context_t context)
{
    auto requestData = reinterpret_cast<const dcmi::GetPowerLimitRequest*>
                   (request);
    std::vector<uint8_t> outPayload(sizeof(dcmi::GetPowerLimitResponse));
    auto responseData = reinterpret_cast<dcmi::GetPowerLimitResponse*>
            (outPayload.data());

    if (requestData->groupID != dcmi::groupExtId)
    {
        *data_len = 0;
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    sdbusplus::bus::bus sdbus {ipmid_get_sd_bus_connection()};
    uint32_t pcapValue = 0;
    bool pcapEnable = false;

    try
    {
        pcapValue = dcmi::getPcap(sdbus);
        pcapEnable = dcmi::getPcapEnabled(sdbus);
    }
    catch (InternalFailure& e)
    {
        *data_len = 0;
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    responseData->groupID = dcmi::groupExtId;

    /*
     * Exception action if power limit is exceeded and cannot be controlled
     * with the correction time limit is hardcoded to Hard Power Off system
     * and log event to SEL.
     */
    constexpr auto exception = 0x01;
    responseData->exceptionAction = exception;

    responseData->powerLimit = static_cast<uint16_t>(pcapValue);

    /*
     * Correction time limit and Statistics sampling period is currently not
     * populated.
     */

    *data_len = outPayload.size();
    memcpy(response, outPayload.data(), *data_len);

    if (pcapEnable)
    {
        return IPMI_CC_OK;
    }
    else
    {
        return IPMI_DCMI_CC_NO_ACTIVE_POWER_LIMIT;
    }
}

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
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_GRPEXT, IPMI_CMD_DCMI_GET_POWER_LIMIT);
    ipmi_register_callback(NETFUN_GRPEXT, IPMI_CMD_DCMI_GET_POWER_LIMIT, NULL, getPowerLimit,
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
