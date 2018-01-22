#include "dcmihandler.hpp"
#include "host-ipmid/ipmid-api.h"
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <nlohmann/json.hpp>
#include "utils.hpp"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <fstream>
#include "xyz/openbmc_project/Common/error.hpp"
#include "config.h"

using namespace phosphor::logging;
using InternalFailure =
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

void register_netfn_dcmi_functions() __attribute__((constructor));

constexpr auto PCAP_PATH    = "/xyz/openbmc_project/control/host0/power_cap";
constexpr auto PCAP_INTERFACE = "xyz.openbmc_project.Control.Power.Cap";

constexpr auto POWER_CAP_PROP = "PowerCap";
constexpr auto POWER_CAP_ENABLE_PROP = "PowerCapEnable";

constexpr auto SENSOR_VALUE_INTF = "xyz.openbmc_project.Sensor.Value";
constexpr auto SENSOR_VALUE_PROP = "Value";
constexpr auto SENSOR_SCALE_PROP = "Scale";

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

void setPcap(sdbusplus::bus::bus& bus, const uint32_t powerCap)
{
    auto service = ipmi::getService(bus, PCAP_INTERFACE, PCAP_PATH);

    auto method = bus.new_method_call(service.c_str(),
                                      PCAP_PATH,
                                      "org.freedesktop.DBus.Properties",
                                      "Set");

    method.append(PCAP_INTERFACE, POWER_CAP_PROP);
    method.append(sdbusplus::message::variant<uint32_t>(powerCap));

    auto reply = bus.call(method);

    if (reply.is_method_error())
    {
        log<level::ERR>("Error in setPcap property");
        elog<InternalFailure>();
    }
}

void setPcapEnable(sdbusplus::bus::bus& bus, bool enabled)
{
    auto service = ipmi::getService(bus, PCAP_INTERFACE, PCAP_PATH);

    auto method = bus.new_method_call(service.c_str(),
                                      PCAP_PATH,
                                      "org.freedesktop.DBus.Properties",
                                      "Set");

    method.append(PCAP_INTERFACE, POWER_CAP_ENABLE_PROP);
    method.append(sdbusplus::message::variant<bool>(enabled));

    auto reply = bus.call(method);

    if (reply.is_method_error())
    {
        log<level::ERR>("Error in setPcapEnabled property");
        elog<InternalFailure>();
    }
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

std::string getHostName(void)
{
    sdbusplus::bus::bus bus{ ipmid_get_sd_bus_connection() };

    auto service = ipmi::getService(bus, networkConfigIntf, networkConfigObj);
    auto value = ipmi::getDbusProperty(bus, service,
        networkConfigObj, networkConfigIntf, hostNameProp);

    return value.get<std::string>();
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

ipmi_ret_t setPowerLimit(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                         ipmi_request_t request, ipmi_response_t response,
                         ipmi_data_len_t data_len, ipmi_context_t context)
{
    auto requestData = reinterpret_cast<const dcmi::SetPowerLimitRequest*>
                   (request);
    std::vector<uint8_t> outPayload(sizeof(dcmi::SetPowerLimitResponse));
    auto responseData = reinterpret_cast<dcmi::SetPowerLimitResponse*>
            (outPayload.data());

    if (requestData->groupID != dcmi::groupExtId)
    {
        *data_len = 0;
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    sdbusplus::bus::bus sdbus {ipmid_get_sd_bus_connection()};

    // Only process the power limit requested in watts.
    try
    {
        dcmi::setPcap(sdbus, requestData->powerLimit);
    }
    catch (InternalFailure& e)
    {
        *data_len = 0;
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    log<level::INFO>("Set Power Cap",
                     entry("POWERCAP=%u", requestData->powerLimit));

    responseData->groupID = dcmi::groupExtId;
    memcpy(response, outPayload.data(), outPayload.size());
    *data_len = outPayload.size();

    return IPMI_CC_OK;
}

ipmi_ret_t applyPowerLimit(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                           ipmi_request_t request, ipmi_response_t response,
                           ipmi_data_len_t data_len, ipmi_context_t context)
{
    auto requestData = reinterpret_cast<const dcmi::ApplyPowerLimitRequest*>
                   (request);
    std::vector<uint8_t> outPayload(sizeof(dcmi::ApplyPowerLimitResponse));
    auto responseData = reinterpret_cast<dcmi::ApplyPowerLimitResponse*>
            (outPayload.data());

    if (requestData->groupID != dcmi::groupExtId)
    {
        *data_len = 0;
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    sdbusplus::bus::bus sdbus {ipmid_get_sd_bus_connection()};

    try
    {
        dcmi::setPcapEnable(sdbus,
                            static_cast<bool>(requestData->powerLimitAction));
    }
    catch (InternalFailure& e)
    {
        *data_len = 0;
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    log<level::INFO>("Set Power Cap Enable",
                     entry("POWERCAPENABLE=%u", requestData->powerLimitAction));

    responseData->groupID = dcmi::groupExtId;
    memcpy(response, outPayload.data(), outPayload.size());
    *data_len = outPayload.size();

    return IPMI_CC_OK;
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

ipmi_ret_t getMgmntCtrlIdStr(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
    ipmi_request_t request, ipmi_response_t response,
    ipmi_data_len_t data_len, ipmi_context_t context)
{
    auto requestData = reinterpret_cast<const dcmi::GetMgmntCtrlIdStrRequest *>
        (request);
    auto responseData = reinterpret_cast<dcmi::GetMgmntCtrlIdStrResponse *>
        (response);
    std::string hostName;

    *data_len = 0;

    if (requestData->groupID != dcmi::groupExtId ||
        requestData->bytes > dcmi::maxBytes ||
        requestData->offset + requestData->bytes > dcmi::maxCtrlIdStrLen)
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    try
    {
        hostName = dcmi::getHostName();
    }
    catch (InternalFailure& e)
    {
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    if (requestData->offset > hostName.length())
    {
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }
    auto responseStr = hostName.substr(requestData->offset, requestData->bytes);
    auto responseStrLen = std::min(static_cast<std::size_t>(requestData->bytes),
        responseStr.length() + 1);
    responseData->groupID = dcmi::groupExtId;
    responseData->strLen = hostName.length();
    std::copy(begin(responseStr), end(responseStr), responseData->data);

    *data_len = sizeof(*responseData) + responseStrLen;
    return IPMI_CC_OK;
}

ipmi_ret_t setMgmntCtrlIdStr(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
    ipmi_request_t request, ipmi_response_t response,
    ipmi_data_len_t data_len, ipmi_context_t context)
{
    static std::array<char, dcmi::maxCtrlIdStrLen + 1> newCtrlIdStr;

    auto requestData = reinterpret_cast<const dcmi::SetMgmntCtrlIdStrRequest *>
        (request);
    auto responseData = reinterpret_cast<dcmi::SetMgmntCtrlIdStrResponse *>
        (response);

    *data_len = 0;

    if (requestData->groupID != dcmi::groupExtId ||
        requestData->bytes > dcmi::maxBytes ||
        requestData->offset + requestData->bytes > dcmi::maxCtrlIdStrLen + 1 ||
        (requestData->offset + requestData->bytes == dcmi::maxCtrlIdStrLen + 1 &&
            requestData->data[requestData->bytes - 1] != '\0'))
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    try
    {
        /* if there is no old value and offset is not 0 */
        if (newCtrlIdStr[0] == '\0' && requestData->offset != 0)
        {
            /* read old ctrlIdStr */
            auto hostName = dcmi::getHostName();
            hostName.resize(dcmi::maxCtrlIdStrLen);
            std::copy(begin(hostName), end(hostName), begin(newCtrlIdStr));
            newCtrlIdStr[hostName.length()] = '\0';
        }

        /* replace part of string and mark byte after the last as \0 */
        auto restStrIter = std::copy_n(requestData->data,
            requestData->bytes, begin(newCtrlIdStr) + requestData->offset);
        /* if the last written byte is not 64th - add '\0' */
        if (requestData->offset + requestData->bytes <= dcmi::maxCtrlIdStrLen)
        {
            *restStrIter = '\0';
        }

        /* if input data contains '\0' whole string is sent - update hostname */
        auto it = std::find(requestData->data,
            requestData->data + requestData->bytes, '\0');
        if (it != requestData->data + requestData->bytes)
        {
            sdbusplus::bus::bus bus{ ipmid_get_sd_bus_connection() };
            ipmi::setDbusProperty(bus, dcmi::networkServiceName,
                dcmi::networkConfigObj, dcmi::networkConfigIntf,
                dcmi::hostNameProp, std::string(newCtrlIdStr.data()));
        }
    }
    catch (InternalFailure& e)
    {
        *data_len = 0;
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    responseData->groupID = dcmi::groupExtId;
    responseData->offset = requestData->offset + requestData->bytes;
    *data_len = sizeof(*responseData);
    return IPMI_CC_OK;
}

int64_t getPowerReading(sdbusplus::bus::bus& bus)
{
    std::ifstream sensorFile(POWER_READING_SENSOR);
    std::string objectPath;
    if (!sensorFile.is_open())
    {
        log<level::ERR>("Power reading configuration file not found",
                    entry("POWER_SENSOR_FILE=%s", POWER_READING_SENSOR));
        elog<InternalFailure>();
    }

    auto data = nlohmann::json::parse(sensorFile, nullptr, false);
    if (data.is_discarded())
    {
        log<level::ERR>("Error in parsing configuration file",
                    entry("POWER_SENSOR_FILE=%s", POWER_READING_SENSOR));
        elog<InternalFailure>();
    }

    objectPath = data.value("path", "");
    if (objectPath.empty())
    {
        log<level::ERR>("Power sensor D-Bus object path is empty",
                        entry("POWER_SENSOR_FILE=%s", POWER_READING_SENSOR));
        elog<InternalFailure>();
    }

    auto service = ipmi::getService(bus, SENSOR_VALUE_INTF, objectPath);

    //Read the sensor value and scale properties
    auto properties = ipmi::getAllDbusProperties(
                            bus, service, objectPath, SENSOR_VALUE_INTF);
    auto power = properties[SENSOR_VALUE_PROP].get<int64_t>();
    auto scale = properties[SENSOR_SCALE_PROP].get<int64_t>();

    //int64_t power  = value;
    // Power reading needs to be scaled with the Scale value using the formula
    // Value * 10^Scale.
    power *= std::pow(10, scale);

    return power;
}

ipmi_ret_t getPowerReading(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
            ipmi_request_t request, ipmi_response_t response,
            ipmi_data_len_t data_len, ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    auto requestData = reinterpret_cast<const dcmi::GetPowerReadingRequest*>
                   (request);
    auto responseData = reinterpret_cast<dcmi::GetPowerReadingResponse*>
            (response);

    if (requestData->groupID != dcmi::groupExtId)
    {
        *data_len = 0;
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    int64_t power = 0;
    try
    {
        power = getPowerReading(bus);
    }
    catch (InternalFailure& e)
    {
        log<level::ERR>("Error in reading power sensor value",
                        entry("INTERFACE=%s", SENSOR_VALUE_INTF),
                        entry("PROPERTY=%s", SENSOR_VALUE_PROP));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    responseData->groupID = dcmi::groupExtId;

    // TODO: openbmc/openbmc#2819
    // Minumum, Maximum, Average power, TimeFrame, TimeStamp,
    // PowerReadingState readings need to be populated
    // after Telemetry changes.
    uint16_t totalPower = static_cast<uint16_t>(power);
    responseData->currentPower = totalPower;
    responseData->minimumPower = totalPower;
    responseData->maximumPower = totalPower;
    responseData->averagePower = totalPower;

    *data_len = sizeof(*responseData);
    return rc;
}


void register_netfn_dcmi_functions()
{
    // <Get Power Limit>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",
            NETFUN_GRPEXT, dcmi::Commands::GET_POWER_LIMIT);

    ipmi_register_callback(NETFUN_GRPEXT, dcmi::Commands::GET_POWER_LIMIT,
                           NULL, getPowerLimit, PRIVILEGE_USER);

    // <Set Power Limit>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",
            NETFUN_GRPEXT, dcmi::Commands::SET_POWER_LIMIT);

    ipmi_register_callback(NETFUN_GRPEXT, dcmi::Commands::SET_POWER_LIMIT,
                           NULL, setPowerLimit, PRIVILEGE_OPERATOR);

    // <Activate/Deactivate Power Limit>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",
            NETFUN_GRPEXT, dcmi::Commands::APPLY_POWER_LIMIT);

    ipmi_register_callback(NETFUN_GRPEXT, dcmi::Commands::APPLY_POWER_LIMIT,
                           NULL, applyPowerLimit, PRIVILEGE_OPERATOR);

    // <Get Asset Tag>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",
            NETFUN_GRPEXT, dcmi::Commands::GET_ASSET_TAG);

    ipmi_register_callback(NETFUN_GRPEXT, dcmi::Commands::GET_ASSET_TAG,
                           NULL, getAssetTag, PRIVILEGE_USER);

    // <Set Asset Tag>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",
            NETFUN_GRPEXT, dcmi::Commands::SET_ASSET_TAG);

    ipmi_register_callback(NETFUN_GRPEXT, dcmi::Commands::SET_ASSET_TAG,
                           NULL, setAssetTag, PRIVILEGE_OPERATOR);

    // <Get Management Controller Identifier String>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",
        NETFUN_GRPEXT, dcmi::Commands::GET_MGMNT_CTRL_ID_STR);

    ipmi_register_callback(NETFUN_GRPEXT, dcmi::Commands::GET_MGMNT_CTRL_ID_STR,
        NULL, getMgmntCtrlIdStr, PRIVILEGE_USER);

    // <Set Management Controller Identifier String>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",
        NETFUN_GRPEXT, dcmi::Commands::SET_MGMNT_CTRL_ID_STR);
    ipmi_register_callback(NETFUN_GRPEXT, dcmi::Commands::SET_MGMNT_CTRL_ID_STR,
        NULL, setMgmntCtrlIdStr, PRIVILEGE_ADMIN);

    // <Get Power Reading>
    ipmi_register_callback(NETFUN_GRPEXT, dcmi::Commands::GET_POWER_READING,
                           NULL, getPowerReading, PRIVILEGE_USER);
    return;
}
// 956379
