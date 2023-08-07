#include "config.h"

#include "dcmihandler.hpp"

#include "user_channel/channel_layer.hpp"

#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <nlohmann/json.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/Network/EthernetInterface/server.hpp>

#include <bitset>
#include <cmath>
#include <fstream>
#include <variant>

using namespace phosphor::logging;
using sdbusplus::xyz::openbmc_project::Network::server::EthernetInterface;

using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

void register_netfn_dcmi_functions() __attribute__((constructor));

constexpr auto pcapPath = "/xyz/openbmc_project/control/host0/power_cap";
constexpr auto pcapInterface = "xyz.openbmc_project.Control.Power.Cap";

constexpr auto powerCapProp = "PowerCap";
constexpr auto powerCapEnableProp = "PowerCapEnable";

constexpr auto DCMI_SPEC_MAJOR_VERSION = 1;
constexpr auto DCMI_SPEC_MINOR_VERSION = 5;
constexpr auto DCMI_CONFIG_PARAMETER_REVISION = 1;
constexpr auto DCMI_RAND_BACK_OFF_MASK = 0x80;
constexpr auto DCMI_OPTION_60_43_MASK = 0x02;
constexpr auto DCMI_OPTION_12_MASK = 0x01;
constexpr auto DCMI_ACTIVATE_DHCP_MASK = 0x01;
constexpr auto DCMI_ACTIVATE_DHCP_REPLY = 0x00;
constexpr auto DCMI_SET_CONF_PARAM_REQ_PACKET_MAX_SIZE = 0x04;
constexpr auto DCMI_SET_CONF_PARAM_REQ_PACKET_MIN_SIZE = 0x03;
constexpr auto DHCP_TIMING1 = 0x04;       // 4 sec
constexpr auto DHCP_TIMING2_UPPER = 0x00; // 2 min
constexpr auto DHCP_TIMING2_LOWER = 0x78;
constexpr auto DHCP_TIMING3_UPPER = 0x00; // 64 sec
constexpr auto DHCP_TIMING3_LOWER = 0x40;
// When DHCP Option 12 is enabled the string "SendHostName=true" will be
// added into n/w configuration file and the parameter
// SendHostNameEnabled will set to true.
constexpr auto DHCP_OPT12_ENABLED = "SendHostNameEnabled";

constexpr auto SENSOR_VALUE_INTF = "xyz.openbmc_project.Sensor.Value";
constexpr auto SENSOR_VALUE_PROP = "Value";

using namespace phosphor::logging;

namespace dcmi
{
constexpr auto assetTagMaxOffset = 62;
constexpr auto assetTagMaxSize = 63;
constexpr auto maxBytes = 16;
constexpr size_t maxCtrlIdStrLen = 63;

constexpr uint8_t parameterRevision = 2;
constexpr uint8_t specMajorVersion = 1;
constexpr uint8_t specMinorVersion = 5;

// Refer Table 6-14, DCMI Entity ID Extension, DCMI v1.5 spec
static const std::map<uint8_t, std::string> entityIdToName{
    {0x40, "inlet"}, {0x37, "inlet"},     {0x41, "cpu"},
    {0x03, "cpu"},   {0x42, "baseboard"}, {0x07, "baseboard"}};

bool isDCMIPowerMgmtSupported()
{
    static bool parsed = false;
    static bool supported = false;
    if (!parsed)
    {
        auto data = parseJSONConfig(gDCMICapabilitiesConfig);

        supported = (gDCMIPowerMgmtSupported ==
                     data.value(gDCMIPowerMgmtCapability, 0));
    }
    return supported;
}

std::optional<uint32_t> getPcap(ipmi::Context::ptr& ctx)
{
    std::string service{};
    boost::system::error_code ec = ipmi::getService(ctx, pcapInterface,
                                                    pcapPath, service);
    if (ec.value())
    {
        return std::nullopt;
    }
    uint32_t pcap{};
    ec = ipmi::getDbusProperty(ctx, service, pcapPath, pcapInterface,
                               powerCapProp, pcap);
    if (ec.value())
    {
        log<level::ERR>("Error in getPcap prop",
                        entry("ERROR=%s", ec.message().c_str()));
        elog<InternalFailure>();
        return std::nullopt;
    }
    return pcap;
}

std::optional<bool> getPcapEnabled(ipmi::Context::ptr& ctx)
{
    std::string service{};
    boost::system::error_code ec = ipmi::getService(ctx, pcapInterface,
                                                    pcapPath, service);
    if (ec.value())
    {
        return std::nullopt;
    }
    bool pcapEnabled{};
    ec = ipmi::getDbusProperty(ctx, service, pcapPath, pcapInterface,
                               powerCapEnableProp, pcapEnabled);
    if (ec.value())
    {
        log<level::ERR>("Error in getPcap prop");
        elog<InternalFailure>();
        return std::nullopt;
    }
    return pcapEnabled;
}

bool setPcap(ipmi::Context::ptr& ctx, const uint32_t powerCap)
{
    std::string service{};
    boost::system::error_code ec = ipmi::getService(ctx, pcapInterface,
                                                    pcapPath, service);
    if (ec.value())
    {
        return false;
    }

    ec = ipmi::setDbusProperty(ctx, service, pcapPath, pcapInterface,
                               powerCapProp, powerCap);
    if (ec.value())
    {
        log<level::ERR>("Error in setPcap property",
                        entry("ERROR=%s", ec.message().c_str()));
        elog<InternalFailure>();
        return false;
    }
    return true;
}

bool setPcapEnable(ipmi::Context::ptr& ctx, bool enabled)
{
    std::string service{};
    boost::system::error_code ec = ipmi::getService(ctx, pcapInterface,
                                                    pcapPath, service);
    if (ec.value())
    {
        return false;
    }

    ec = ipmi::setDbusProperty(ctx, service, pcapPath, pcapInterface,
                               powerCapEnableProp, enabled);
    if (ec.value())
    {
        log<level::ERR>("Error in setPcapEnabled property",
                        entry("ERROR=%s", ec.message().c_str()));
        elog<InternalFailure>();
        return false;
    }
    return true;
}

std::optional<std::string> readAssetTag(ipmi::Context::ptr& ctx)
{
    // Read the object tree with the inventory root to figure out the object
    // that has implemented the Asset tag interface.
    ipmi::DbusObjectInfo objectInfo;
    boost::system::error_code ec = getDbusObject(
        ctx, dcmi::assetTagIntf, ipmi::sensor::inventoryRoot, "", objectInfo);
    if (ec.value())
    {
        return std::nullopt;
    }

    std::string assetTag{};
    ec = ipmi::getDbusProperty(ctx, objectInfo.second, objectInfo.first,
                               dcmi::assetTagIntf, dcmi::assetTagProp,
                               assetTag);
    if (ec.value())
    {
        log<level::ERR>("Error in reading asset tag",
                        entry("ERROR=%s", ec.message().c_str()));
        elog<InternalFailure>();
        return std::nullopt;
    }

    return assetTag;
}

bool writeAssetTag(ipmi::Context::ptr& ctx, const std::string& assetTag)
{
    // Read the object tree with the inventory root to figure out the object
    // that has implemented the Asset tag interface.
    ipmi::DbusObjectInfo objectInfo;
    boost::system::error_code ec = getDbusObject(
        ctx, dcmi::assetTagIntf, ipmi::sensor::inventoryRoot, "", objectInfo);
    if (ec.value())
    {
        return false;
    }

    ec = ipmi::setDbusProperty(ctx, objectInfo.second, objectInfo.first,
                               dcmi::assetTagIntf, dcmi::assetTagProp,
                               assetTag);
    if (ec.value())
    {
        log<level::ERR>("Error in writing asset tag",
                        entry("ERROR=%s", ec.message().c_str()));
        elog<InternalFailure>();
        return false;
    }
    return true;
}

std::optional<std::string> getHostName(ipmi::Context::ptr& ctx)
{
    std::string service{};
    boost::system::error_code ec = ipmi::getService(ctx, networkConfigIntf,
                                                    networkConfigObj, service);
    if (ec.value())
    {
        return std::nullopt;
    }
    std::string hostname{};
    ec = ipmi::getDbusProperty(ctx, service, networkConfigObj,
                               networkConfigIntf, hostNameProp, hostname);
    if (ec.value())
    {
        log<level::ERR>("Error fetching hostname");
        elog<InternalFailure>();
        return std::nullopt;
    }
    return hostname;
}

EthernetInterface::DHCPConf getDHCPEnabled()
{
    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};

    auto ethdevice = ipmi::getChannelName(ethernetDefaultChannelNum);
    auto ethernetObj = ipmi::getDbusObject(bus, ethernetIntf, networkRoot,
                                           ethdevice);
    auto service = ipmi::getService(bus, ethernetIntf, ethernetObj.first);
    auto value = ipmi::getDbusProperty(bus, service, ethernetObj.first,
                                       ethernetIntf, "DHCPEnabled");

    return EthernetInterface::convertDHCPConfFromString(
        std::get<std::string>(value));
}

bool getDHCPOption(std::string prop)
{
    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};

    auto service = ipmi::getService(bus, dhcpIntf, dhcpObj);
    auto value = ipmi::getDbusProperty(bus, service, dhcpObj, dhcpIntf, prop);

    return std::get<bool>(value);
}

void setDHCPOption(std::string prop, bool value)
{
    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};

    auto service = ipmi::getService(bus, dhcpIntf, dhcpObj);
    ipmi::setDbusProperty(bus, service, dhcpObj, dhcpIntf, prop, value);
}

Json parseJSONConfig(const std::string& configFile)
{
    std::ifstream jsonFile(configFile);
    if (!jsonFile.is_open())
    {
        log<level::ERR>("Temperature readings JSON file not found");
        elog<InternalFailure>();
    }

    auto data = Json::parse(jsonFile, nullptr, false);
    if (data.is_discarded())
    {
        log<level::ERR>("Temperature readings JSON parser failure");
        elog<InternalFailure>();
    }

    return data;
}

} // namespace dcmi

constexpr uint8_t exceptionPowerOff = 0x01;
ipmi::RspType<uint16_t, // reserved
              uint8_t,  // exception actions
              uint16_t, // power limit requested in watts
              uint32_t, // correction time in milliseconds
              uint16_t, // reserved
              uint16_t  // statistics sampling period in seconds
              >
    getPowerLimit(ipmi::Context::ptr ctx, uint16_t reserved)
{
    if (!dcmi::isDCMIPowerMgmtSupported())
    {
        return ipmi::responseInvalidCommand();
    }
    if (reserved)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    std::optional<uint16_t> pcapValue = dcmi::getPcap(ctx);
    std::optional<bool> pcapEnable = dcmi::getPcapEnabled(ctx);
    if (!pcapValue || !pcapEnable)
    {
        return ipmi::responseUnspecifiedError();
    }

    constexpr uint16_t reserved1{};
    constexpr uint16_t reserved2{};
    /*
     * Exception action if power limit is exceeded and cannot be controlled
     * with the correction time limit is hardcoded to Hard Power Off system
     * and log event to SEL.
     */
    constexpr uint8_t exception = exceptionPowerOff;
    /*
     * Correction time limit and Statistics sampling period is currently not
     * populated.
     */
    constexpr uint32_t correctionTime{};
    constexpr uint16_t statsPeriod{};
    if (!pcapEnable)
    {
        constexpr ipmi::Cc responseNoPowerLimitSet = 0x80;
        constexpr uint16_t noPcap{};
        return ipmi::response(responseNoPowerLimitSet, reserved1, exception,
                              noPcap, correctionTime, reserved2, statsPeriod);
    }
    return ipmi::responseSuccess(reserved1, exception, *pcapValue,
                                 correctionTime, reserved2, statsPeriod);
}

ipmi::RspType<> setPowerLimit(ipmi::Context::ptr& ctx, uint16_t reserved1,
                              uint8_t exceptionAction, uint16_t powerLimit,
                              uint32_t correctionTime, uint16_t reserved2,
                              uint16_t statsPeriod)
{
    if (!dcmi::isDCMIPowerMgmtSupported())
    {
        log<level::ERR>("DCMI Power management is unsupported!");
        return ipmi::responseInvalidCommand();
    }

    // Only process the power limit requested in watts. Return errors
    // for other fields that are set
    if (reserved1 || reserved2 || correctionTime || statsPeriod ||
        exceptionAction != exceptionPowerOff)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    if (!dcmi::setPcap(ctx, powerLimit))
    {
        return ipmi::responseUnspecifiedError();
    }

    log<level::INFO>("Set Power Cap", entry("POWERCAP=%u", powerLimit));

    return ipmi::responseSuccess();
}

ipmi::RspType<> applyPowerLimit(ipmi::Context::ptr& ctx, bool enabled,
                                uint7_t reserved1, uint16_t reserved2)
{
    if (!dcmi::isDCMIPowerMgmtSupported())
    {
        log<level::ERR>("DCMI Power management is unsupported!");
        return ipmi::responseInvalidCommand();
    }
    if (reserved1 || reserved2)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    if (!dcmi::setPcapEnable(ctx, enabled))
    {
        return ipmi::responseUnspecifiedError();
    }

    log<level::INFO>("Set Power Cap Enable",
                     entry("POWERCAPENABLE=%u", static_cast<uint8_t>(enabled)));

    return ipmi::responseSuccess();
}

ipmi::RspType<uint8_t,          // total tag length
              std::vector<char> // tag data
              >
    getAssetTag(ipmi::Context::ptr& ctx, uint8_t offset, uint8_t count)
{
    // Verify offset to read and number of bytes to read are not exceeding
    // the range.
    if ((offset > dcmi::assetTagMaxOffset) || (count > dcmi::maxBytes) ||
        ((offset + count) > dcmi::assetTagMaxSize))
    {
        return ipmi::responseParmOutOfRange();
    }

    std::optional<std::string> assetTagResp = dcmi::readAssetTag(ctx);
    if (!assetTagResp)
    {
        return ipmi::responseUnspecifiedError();
    }

    std::string& assetTag = assetTagResp.value();
    // If the asset tag is longer than 63 bytes, restrict it to 63 bytes to
    // suit Get Asset Tag command.
    if (assetTag.size() > dcmi::assetTagMaxSize)
    {
        assetTag.resize(dcmi::assetTagMaxSize);
    }

    if (offset >= assetTag.size())
    {
        return ipmi::responseParmOutOfRange();
    }

    // silently truncate reads beyond the end of assetTag
    if ((offset + count) >= assetTag.size())
    {
        count = assetTag.size() - offset;
    }

    auto totalTagSize = static_cast<uint8_t>(assetTag.size());
    std::vector<char> data{assetTag.begin() + offset,
                           assetTag.begin() + offset + count};

    return ipmi::responseSuccess(totalTagSize, data);
}

ipmi::RspType<uint8_t // new asset tag length
              >
    setAssetTag(ipmi::Context::ptr& ctx, uint8_t offset, uint8_t count,
                const std::vector<char>& data)
{
    // Verify offset to read and number of bytes to read are not exceeding
    // the range.
    if ((offset > dcmi::assetTagMaxOffset) || (count > dcmi::maxBytes) ||
        ((offset + count) > dcmi::assetTagMaxSize))
    {
        return ipmi::responseParmOutOfRange();
    }
    if (data.size() != count)
    {
        return ipmi::responseReqDataLenInvalid();
    }

    std::optional<std::string> assetTagResp = dcmi::readAssetTag(ctx);
    if (!assetTagResp)
    {
        return ipmi::responseUnspecifiedError();
    }

    std::string& assetTag = assetTagResp.value();

    if (offset > assetTag.size())
    {
        return ipmi::responseParmOutOfRange();
    }

    // operation is to truncate at offset and append new data
    assetTag.resize(offset);
    assetTag.append(data.begin(), data.end());

    if (!dcmi::writeAssetTag(ctx, assetTag))
    {
        return ipmi::responseUnspecifiedError();
    }

    auto totalTagSize = static_cast<uint8_t>(assetTag.size());
    return ipmi::responseSuccess(totalTagSize);
}

ipmi::RspType<uint8_t,          // length
              std::vector<char> // data
              >
    getMgmntCtrlIdStr(ipmi::Context::ptr& ctx, uint8_t offset, uint8_t count)
{
    if (count > dcmi::maxBytes || offset + count > dcmi::maxCtrlIdStrLen)
    {
        return ipmi::responseParmOutOfRange();
    }

    std::optional<std::string> hostnameResp = dcmi::getHostName(ctx);
    if (!hostnameResp)
    {
        return ipmi::responseUnspecifiedError();
    }

    std::string& hostname = hostnameResp.value();
    // If the id string is longer than 63 bytes, restrict it to 63 bytes to
    // suit set management ctrl str  command.
    if (hostname.size() > dcmi::maxCtrlIdStrLen)
    {
        hostname.resize(dcmi::maxCtrlIdStrLen);
    }

    if (offset >= hostname.size())
    {
        return ipmi::responseParmOutOfRange();
    }

    // silently truncate reads beyond the end of hostname
    if ((offset + count) >= hostname.size())
    {
        count = hostname.size() - offset;
    }

    auto nameSize = static_cast<uint8_t>(hostname.size());
    std::vector<char> data{hostname.begin() + offset,
                           hostname.begin() + offset + count};

    return ipmi::responseSuccess(nameSize, data);
}

ipmi::RspType<uint8_t> setMgmntCtrlIdStr(ipmi::Context::ptr& ctx,
                                         uint8_t offset, uint8_t count,
                                         std::vector<char> data)
{
    if ((offset > dcmi::maxCtrlIdStrLen) || (count > dcmi::maxBytes) ||
        ((offset + count) > dcmi::maxCtrlIdStrLen))
    {
        return ipmi::responseParmOutOfRange();
    }
    if (data.size() != count)
    {
        return ipmi::responseReqDataLenInvalid();
    }
    bool terminalWrite{data.back() == '\0'};
    if (terminalWrite)
    {
        // remove the null termination from the data (no need with std::string)
        data.resize(count - 1);
    }

    static std::string hostname{};
    // read in the current value if not starting at offset 0
    if (hostname.size() == 0 && offset != 0)
    {
        /* read old ctrlIdStr */
        std::optional<std::string> hostnameResp = dcmi::getHostName(ctx);
        if (!hostnameResp)
        {
            return ipmi::responseUnspecifiedError();
        }
        hostname = hostnameResp.value();
        hostname.resize(offset);
    }

    // operation is to truncate at offset and append new data
    hostname.append(data.begin(), data.end());

    // do the update if this is the last write
    if (terminalWrite)
    {
        boost::system::error_code ec = ipmi::setDbusProperty(
            ctx, dcmi::networkServiceName, dcmi::networkConfigObj,
            dcmi::networkConfigIntf, dcmi::hostNameProp, hostname);
        hostname.clear();
        if (ec.value())
        {
            return ipmi::responseUnspecifiedError();
        }
    }

    auto totalIdSize = static_cast<uint8_t>(offset + count);
    return ipmi::responseSuccess(totalIdSize);
}

ipmi::RspType<ipmi::message::Payload> getDCMICapabilities(uint8_t parameter)
{
    std::ifstream dcmiCapFile(dcmi::gDCMICapabilitiesConfig);
    if (!dcmiCapFile.is_open())
    {
        log<level::ERR>("DCMI Capabilities file not found");
        return ipmi::responseUnspecifiedError();
    }

    auto data = nlohmann::json::parse(dcmiCapFile, nullptr, false);
    if (data.is_discarded())
    {
        log<level::ERR>("DCMI Capabilities JSON parser failure");
        return ipmi::responseUnspecifiedError();
    }

    constexpr bool reserved1{};
    constexpr uint5_t reserved5{};
    constexpr uint7_t reserved7{};
    constexpr uint8_t reserved8{};
    constexpr uint16_t reserved16{};

    ipmi::message::Payload payload;
    payload.pack(dcmi::specMajorVersion, dcmi::specMinorVersion,
                 dcmi::parameterRevision);

    enum class DCMICapParameters : uint8_t
    {
        SupportedDcmiCaps = 0x01,             // Supported DCMI Capabilities
        MandatoryPlatAttributes = 0x02,       // Mandatory Platform Attributes
        OptionalPlatAttributes = 0x03,        // Optional Platform Attributes
        ManageabilityAccessAttributes = 0x04, // Manageability Access Attributes
    };

    switch (static_cast<DCMICapParameters>(parameter))
    {
        case DCMICapParameters::SupportedDcmiCaps:
        {
            bool powerManagement = data.value("PowerManagement", 0);
            bool oobSecondaryLan = data.value("OOBSecondaryLan", 0);
            bool serialTMode = data.value("SerialTMODE", 0);
            bool inBandSystemInterfaceChannel =
                data.value("InBandSystemInterfaceChannel", 0);
            payload.pack(reserved8, powerManagement, reserved7,
                         inBandSystemInterfaceChannel, serialTMode,
                         oobSecondaryLan, reserved5);
            break;
        }
            // Mandatory Platform Attributes
        case DCMICapParameters::MandatoryPlatAttributes:
        {
            bool selAutoRollOver = data.value("SELAutoRollOver", 0);
            bool flushEntireSELUponRollOver =
                data.value("FlushEntireSELUponRollOver", 0);
            bool recordLevelSELFlushUponRollOver =
                data.value("RecordLevelSELFlushUponRollOver", 0);
            uint12_t numberOfSELEntries = data.value("NumberOfSELEntries",
                                                     0xcac);
            uint8_t tempMonitoringSamplingFreq =
                data.value("TempMonitoringSamplingFreq", 0);
            payload.pack(numberOfSELEntries, reserved1,
                         recordLevelSELFlushUponRollOver,
                         flushEntireSELUponRollOver, selAutoRollOver,
                         reserved16, tempMonitoringSamplingFreq);
            break;
        }
        // Optional Platform Attributes
        case DCMICapParameters::OptionalPlatAttributes:
        {
            uint7_t powerMgmtDeviceSlaveAddress =
                data.value("PowerMgmtDeviceSlaveAddress", 0);
            uint4_t bmcChannelNumber = data.value("BMCChannelNumber", 0);
            uint4_t deviceRivision = data.value("DeviceRivision", 0);
            payload.pack(powerMgmtDeviceSlaveAddress, reserved1, deviceRivision,
                         bmcChannelNumber);
            break;
        }
        // Manageability Access Attributes
        case DCMICapParameters::ManageabilityAccessAttributes:
        {
            uint8_t mandatoryPrimaryLanOOBSupport =
                data.value("MandatoryPrimaryLanOOBSupport", 0xff);
            uint8_t optionalSecondaryLanOOBSupport =
                data.value("OptionalSecondaryLanOOBSupport", 0xff);
            uint8_t optionalSerialOOBMTMODECapability =
                data.value("OptionalSerialOOBMTMODECapability", 0xff);
            payload.pack(mandatoryPrimaryLanOOBSupport,
                         optionalSecondaryLanOOBSupport,
                         optionalSerialOOBMTMODECapability);
            break;
        }
        default:
        {
            log<level::ERR>("Invalid input parameter");
            return ipmi::responseInvalidFieldRequest();
        }
    }

    return ipmi::responseSuccess(payload);
}

namespace dcmi
{
namespace temp_readings
{

Temperature readTemp(const std::string& dbusService,
                     const std::string& dbusPath)
{
    // Read the temperature value from d-bus object. Need some conversion.
    // As per the interface xyz.openbmc_project.Sensor.Value, the temperature
    // is an double and in degrees C. It needs to be scaled by using the
    // formula Value * 10^Scale. The ipmi spec has the temperature as a uint8_t,
    // with a separate single bit for the sign.

    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};
    auto result = ipmi::getAllDbusProperties(
        bus, dbusService, dbusPath, "xyz.openbmc_project.Sensor.Value");
    auto temperature = std::visit(ipmi::VariantToDoubleVisitor(),
                                  result.at("Value"));
    double absTemp = std::abs(temperature);

    auto findFactor = result.find("Scale");
    double factor = 0.0;
    if (findFactor != result.end())
    {
        factor = std::visit(ipmi::VariantToDoubleVisitor(), findFactor->second);
    }
    double scale = std::pow(10, factor);

    auto tempDegrees = absTemp * scale;
    // Max absolute temp as per ipmi spec is 128.
    if (tempDegrees > maxTemp)
    {
        tempDegrees = maxTemp;
    }

    return std::make_tuple(static_cast<uint8_t>(tempDegrees),
                           (temperature < 0));
}

std::tuple<Response, NumInstances> read(const std::string& type,
                                        uint8_t instance)
{
    Response response{};
    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};

    if (!instance)
    {
        log<level::ERR>("Expected non-zero instance");
        elog<InternalFailure>();
    }

    auto data = parseJSONConfig(gDCMISensorsConfig);
    static const std::vector<Json> empty{};
    std::vector<Json> readings = data.value(type, empty);
    size_t numInstances = readings.size();
    for (const auto& j : readings)
    {
        uint8_t instanceNum = j.value("instance", 0);
        // Not the instance we're interested in
        if (instanceNum != instance)
        {
            continue;
        }

        std::string path = j.value("dbus", "");
        std::string service;
        try
        {
            service = ipmi::getService(bus, "xyz.openbmc_project.Sensor.Value",
                                       path);
        }
        catch (const std::exception& e)
        {
            log<level::DEBUG>(e.what());
            return std::make_tuple(response, numInstances);
        }

        response.instance = instance;
        uint8_t temp{};
        bool sign{};
        std::tie(temp, sign) = readTemp(service, path);
        response.temperature = temp;
        response.sign = sign;

        // Found the instance we're interested in
        break;
    }

    if (numInstances > maxInstances)
    {
        numInstances = maxInstances;
    }
    return std::make_tuple(response, numInstances);
}

std::tuple<ResponseList, NumInstances> readAll(const std::string& type,
                                               uint8_t instanceStart)
{
    ResponseList response{};
    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};

    size_t numInstances = 0;
    auto data = parseJSONConfig(gDCMISensorsConfig);
    static const std::vector<Json> empty{};
    std::vector<Json> readings = data.value(type, empty);
    numInstances = readings.size();
    for (const auto& j : readings)
    {
        try
        {
            // Max of 8 response data sets
            if (response.size() == maxDataSets)
            {
                break;
            }

            uint8_t instanceNum = j.value("instance", 0);
            // Not in the instance range we're interested in
            if (instanceNum < instanceStart)
            {
                continue;
            }

            std::string path = j.value("dbus", "");
            auto service =
                ipmi::getService(bus, "xyz.openbmc_project.Sensor.Value", path);

            Response r{};
            r.instance = instanceNum;
            uint8_t temp{};
            bool sign{};
            std::tie(temp, sign) = readTemp(service, path);
            r.temperature = temp;
            r.sign = sign;
            response.push_back(r);
        }
        catch (const std::exception& e)
        {
            log<level::DEBUG>(e.what());
            continue;
        }
    }

    if (numInstances > maxInstances)
    {
        numInstances = maxInstances;
    }
    return std::make_tuple(response, numInstances);
}

} // namespace temp_readings
} // namespace dcmi

ipmi_ret_t getTempReadings(ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t request,
                           ipmi_response_t response, ipmi_data_len_t data_len,
                           ipmi_context_t)
{
    auto requestData =
        reinterpret_cast<const dcmi::GetTempReadingsRequest*>(request);
    auto responseData =
        reinterpret_cast<dcmi::GetTempReadingsResponseHdr*>(response);

    if (*data_len != sizeof(dcmi::GetTempReadingsRequest))
    {
        log<level::ERR>("Malformed request data",
                        entry("DATA_SIZE=%d", *data_len));
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    *data_len = 0;

    auto it = dcmi::entityIdToName.find(requestData->entityId);
    if (it == dcmi::entityIdToName.end())
    {
        log<level::ERR>("Unknown Entity ID",
                        entry("ENTITY_ID=%d", requestData->entityId));
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    if (requestData->sensorType != dcmi::temperatureSensorType)
    {
        log<level::ERR>("Invalid sensor type",
                        entry("SENSOR_TYPE=%d", requestData->sensorType));
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    dcmi::temp_readings::ResponseList temps{};
    try
    {
        if (!requestData->entityInstance)
        {
            // Read all instances
            std::tie(temps, responseData->numInstances) =
                dcmi::temp_readings::readAll(it->second,
                                             requestData->instanceStart);
        }
        else
        {
            // Read one instance
            temps.resize(1);
            std::tie(temps[0], responseData->numInstances) =
                dcmi::temp_readings::read(it->second,
                                          requestData->entityInstance);
        }
        responseData->numDataSets = temps.size();
    }
    catch (const InternalFailure& e)
    {
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    size_t payloadSize = temps.size() * sizeof(dcmi::temp_readings::Response);
    if (!temps.empty())
    {
        memcpy(responseData + 1, // copy payload right after the response header
               temps.data(), payloadSize);
    }
    *data_len = sizeof(dcmi::GetTempReadingsResponseHdr) + payloadSize;

    return IPMI_CC_OK;
}

int64_t getPowerReading(sdbusplus::bus_t& bus)
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

    // Return default value if failed to read from D-Bus object
    int64_t power = 0;
    try
    {
        auto service = ipmi::getService(bus, SENSOR_VALUE_INTF, objectPath);

        // Read the sensor value and scale properties
        auto value = ipmi::getDbusProperty(
            bus, service, objectPath, SENSOR_VALUE_INTF, SENSOR_VALUE_PROP);
        power = std::get<double>(value);
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("Failure to read power value from D-Bus object",
                        entry("OBJECT_PATH=%s", objectPath.c_str()),
                        entry("INTERFACE=%s", SENSOR_VALUE_INTF));
    }
    return power;
}

ipmi_ret_t setDCMIConfParams(ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t request,
                             ipmi_response_t, ipmi_data_len_t data_len,
                             ipmi_context_t)
{
    auto requestData =
        reinterpret_cast<const dcmi::SetConfParamsRequest*>(request);

    if (*data_len < DCMI_SET_CONF_PARAM_REQ_PACKET_MIN_SIZE ||
        *data_len > DCMI_SET_CONF_PARAM_REQ_PACKET_MAX_SIZE)
    {
        log<level::ERR>("Invalid Requested Packet size",
                        entry("PACKET SIZE=%d", *data_len));
        *data_len = 0;
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    *data_len = 0;

    try
    {
        // Take action based on the Parameter Selector
        switch (
            static_cast<dcmi::DCMIConfigParameters>(requestData->paramSelect))
        {
            case dcmi::DCMIConfigParameters::ActivateDHCP:

                if ((requestData->data[0] & DCMI_ACTIVATE_DHCP_MASK) &&
                    (dcmi::getDHCPEnabled() !=
                     EthernetInterface::DHCPConf::none))
                {
                    // When these conditions are met we have to trigger DHCP
                    // protocol restart using the latest parameter settings, but
                    // as per n/w manager design, each time when we update n/w
                    // parameters, n/w service is restarted. So we no need to
                    // take any action in this case.
                }
                break;

            case dcmi::DCMIConfigParameters::DiscoveryConfig:

                if (requestData->data[0] & DCMI_OPTION_12_MASK)
                {
                    dcmi::setDHCPOption(DHCP_OPT12_ENABLED, true);
                }
                else
                {
                    dcmi::setDHCPOption(DHCP_OPT12_ENABLED, false);
                }

                // Systemd-networkd doesn't support Random Back off
                if (requestData->data[0] & DCMI_RAND_BACK_OFF_MASK)
                {
                    return IPMI_CC_INVALID;
                }
                break;
            // Systemd-networkd doesn't allow to configure DHCP timigs
            case dcmi::DCMIConfigParameters::DHCPTiming1:
            case dcmi::DCMIConfigParameters::DHCPTiming2:
            case dcmi::DCMIConfigParameters::DHCPTiming3:
            default:
                return IPMI_CC_INVALID;
        }
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(e.what());
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    return IPMI_CC_OK;
}

ipmi_ret_t getDCMIConfParams(ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t request,
                             ipmi_response_t response, ipmi_data_len_t data_len,
                             ipmi_context_t)
{
    auto requestData =
        reinterpret_cast<const dcmi::GetConfParamsRequest*>(request);
    auto responseData =
        reinterpret_cast<dcmi::GetConfParamsResponse*>(response);

    responseData->data[0] = 0x00;

    if (*data_len != sizeof(dcmi::GetConfParamsRequest))
    {
        log<level::ERR>("Invalid Requested Packet size",
                        entry("PACKET SIZE=%d", *data_len));
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    *data_len = 0;

    try
    {
        // Take action based on the Parameter Selector
        switch (
            static_cast<dcmi::DCMIConfigParameters>(requestData->paramSelect))
        {
            case dcmi::DCMIConfigParameters::ActivateDHCP:
                responseData->data[0] = DCMI_ACTIVATE_DHCP_REPLY;
                *data_len = sizeof(dcmi::GetConfParamsResponse) + 1;
                break;
            case dcmi::DCMIConfigParameters::DiscoveryConfig:
                if (dcmi::getDHCPOption(DHCP_OPT12_ENABLED))
                {
                    responseData->data[0] |= DCMI_OPTION_12_MASK;
                }
                *data_len = sizeof(dcmi::GetConfParamsResponse) + 1;
                break;
            // Get below values from Systemd-networkd source code
            case dcmi::DCMIConfigParameters::DHCPTiming1:
                responseData->data[0] = DHCP_TIMING1;
                *data_len = sizeof(dcmi::GetConfParamsResponse) + 1;
                break;
            case dcmi::DCMIConfigParameters::DHCPTiming2:
                responseData->data[0] = DHCP_TIMING2_LOWER;
                responseData->data[1] = DHCP_TIMING2_UPPER;
                *data_len = sizeof(dcmi::GetConfParamsResponse) + 2;
                break;
            case dcmi::DCMIConfigParameters::DHCPTiming3:
                responseData->data[0] = DHCP_TIMING3_LOWER;
                responseData->data[1] = DHCP_TIMING3_UPPER;
                *data_len = sizeof(dcmi::GetConfParamsResponse) + 2;
                break;
            default:
                *data_len = 0;
                return IPMI_CC_INVALID;
        }
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(e.what());
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    responseData->major = DCMI_SPEC_MAJOR_VERSION;
    responseData->minor = DCMI_SPEC_MINOR_VERSION;
    responseData->paramRevision = DCMI_CONFIG_PARAMETER_REVISION;

    return IPMI_CC_OK;
}

ipmi_ret_t getPowerReading(ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t,
                           ipmi_response_t response, ipmi_data_len_t data_len,
                           ipmi_context_t)
{
    *data_len = 0;
    if (!dcmi::isDCMIPowerMgmtSupported())
    {
        log<level::ERR>("DCMI Power management is unsupported!");
        return IPMI_CC_INVALID;
    }

    ipmi_ret_t rc = IPMI_CC_OK;
    auto responseData =
        reinterpret_cast<dcmi::GetPowerReadingResponse*>(response);

    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};
    int64_t power = 0;
    try
    {
        power = getPowerReading(bus);
    }
    catch (const InternalFailure& e)
    {
        log<level::ERR>("Error in reading power sensor value",
                        entry("INTERFACE=%s", SENSOR_VALUE_INTF),
                        entry("PROPERTY=%s", SENSOR_VALUE_PROP));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    // TODO: openbmc/openbmc#2819
    // Minimum, Maximum, Average power, TimeFrame, TimeStamp,
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

namespace dcmi
{
namespace sensor_info
{

Response createFromJson(const Json& config)
{
    Response response{};
    uint16_t recordId = config.value("record_id", 0);
    response.recordIdLsb = recordId & 0xFF;
    response.recordIdMsb = (recordId >> 8) & 0xFF;
    return response;
}

std::tuple<Response, NumInstances> read(const std::string& type,
                                        uint8_t instance, const Json& config)
{
    Response response{};

    if (!instance)
    {
        log<level::ERR>("Expected non-zero instance");
        elog<InternalFailure>();
    }

    static const std::vector<Json> empty{};
    std::vector<Json> readings = config.value(type, empty);
    size_t numInstances = readings.size();
    for (const auto& reading : readings)
    {
        uint8_t instanceNum = reading.value("instance", 0);
        // Not the instance we're interested in
        if (instanceNum != instance)
        {
            continue;
        }

        response = createFromJson(reading);

        // Found the instance we're interested in
        break;
    }

    if (numInstances > maxInstances)
    {
        log<level::DEBUG>("Trimming IPMI num instances",
                          entry("NUM_INSTANCES=%d", numInstances));
        numInstances = maxInstances;
    }
    return std::make_tuple(response, numInstances);
}

std::tuple<ResponseList, NumInstances>
    readAll(const std::string& type, uint8_t instanceStart, const Json& config)
{
    ResponseList responses{};

    size_t numInstances = 0;
    static const std::vector<Json> empty{};
    std::vector<Json> readings = config.value(type, empty);
    numInstances = readings.size();
    for (const auto& reading : readings)
    {
        try
        {
            // Max of 8 records
            if (responses.size() == maxRecords)
            {
                break;
            }

            uint8_t instanceNum = reading.value("instance", 0);
            // Not in the instance range we're interested in
            if (instanceNum < instanceStart)
            {
                continue;
            }

            Response response = createFromJson(reading);
            responses.push_back(response);
        }
        catch (const std::exception& e)
        {
            log<level::DEBUG>(e.what());
            continue;
        }
    }

    if (numInstances > maxInstances)
    {
        log<level::DEBUG>("Trimming IPMI num instances",
                          entry("NUM_INSTANCES=%d", numInstances));
        numInstances = maxInstances;
    }
    return std::make_tuple(responses, numInstances);
}

} // namespace sensor_info
} // namespace dcmi

ipmi_ret_t getSensorInfo(ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t request,
                         ipmi_response_t response, ipmi_data_len_t data_len,
                         ipmi_context_t)
{
    auto requestData =
        reinterpret_cast<const dcmi::GetSensorInfoRequest*>(request);
    auto responseData =
        reinterpret_cast<dcmi::GetSensorInfoResponseHdr*>(response);

    if (*data_len != sizeof(dcmi::GetSensorInfoRequest))
    {
        log<level::ERR>("Malformed request data",
                        entry("DATA_SIZE=%d", *data_len));
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    *data_len = 0;

    auto it = dcmi::entityIdToName.find(requestData->entityId);
    if (it == dcmi::entityIdToName.end())
    {
        log<level::ERR>("Unknown Entity ID",
                        entry("ENTITY_ID=%d", requestData->entityId));
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    if (requestData->sensorType != dcmi::temperatureSensorType)
    {
        log<level::ERR>("Invalid sensor type",
                        entry("SENSOR_TYPE=%d", requestData->sensorType));
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    dcmi::sensor_info::ResponseList sensors{};
    static dcmi::Json config{};
    static bool parsed = false;

    try
    {
        if (!parsed)
        {
            config = dcmi::parseJSONConfig(dcmi::gDCMISensorsConfig);
            parsed = true;
        }

        if (!requestData->entityInstance)
        {
            // Read all instances
            std::tie(sensors, responseData->numInstances) =
                dcmi::sensor_info::readAll(it->second,
                                           requestData->instanceStart, config);
        }
        else
        {
            // Read one instance
            sensors.resize(1);
            std::tie(sensors[0], responseData->numInstances) =
                dcmi::sensor_info::read(it->second, requestData->entityInstance,
                                        config);
        }
        responseData->numRecords = sensors.size();
    }
    catch (const InternalFailure& e)
    {
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    size_t payloadSize = sensors.size() * sizeof(dcmi::sensor_info::Response);
    if (!sensors.empty())
    {
        memcpy(responseData + 1, // copy payload right after the response header
               sensors.data(), payloadSize);
    }
    *data_len = sizeof(dcmi::GetSensorInfoResponseHdr) + payloadSize;

    return IPMI_CC_OK;
}

void register_netfn_dcmi_functions()
{
    // <Get Power Limit>
    registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::groupDCMI,
                         ipmi::dcmi::cmdGetPowerLimit, ipmi::Privilege::User,
                         getPowerLimit);

    // <Set Power Limit>
    registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::groupDCMI,
                         ipmi::dcmi::cmdSetPowerLimit,
                         ipmi::Privilege::Operator, setPowerLimit);

    // <Activate/Deactivate Power Limit>
    registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::groupDCMI,
                         ipmi::dcmi::cmdActDeactivatePwrLimit,
                         ipmi::Privilege::Operator, applyPowerLimit);

    // <Get Asset Tag>
    registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::groupDCMI,
                         ipmi::dcmi::cmdGetAssetTag, ipmi::Privilege::User,
                         getAssetTag);

    // <Set Asset Tag>
    registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::groupDCMI,
                         ipmi::dcmi::cmdSetAssetTag, ipmi::Privilege::Operator,
                         setAssetTag);

    // <Get Management Controller Identifier String>
    registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::groupDCMI,
                         ipmi::dcmi::cmdGetMgmtCntlrIdString,
                         ipmi::Privilege::User, getMgmntCtrlIdStr);

    // <Set Management Controller Identifier String>
    registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::groupDCMI,
                         ipmi::dcmi::cmdSetMgmtCntlrIdString,
                         ipmi::Privilege::Admin, setMgmntCtrlIdStr);

    // <Get DCMI capabilities>
    registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::groupDCMI,
                         ipmi::dcmi::cmdGetDcmiCapabilitiesInfo,
                         ipmi::Privilege::User, getDCMICapabilities);

    // <Get Temperature Readings>
    ipmi_register_callback(NETFUN_GRPEXT, dcmi::Commands::GET_TEMP_READINGS,
                           NULL, getTempReadings, PRIVILEGE_USER);

    // <Get Power Reading>
    ipmi_register_callback(NETFUN_GRPEXT, dcmi::Commands::GET_POWER_READING,
                           NULL, getPowerReading, PRIVILEGE_USER);
// The Get sensor should get the senor details dynamically when
// FEATURE_DYNAMIC_SENSORS is enabled.
#ifndef FEATURE_DYNAMIC_SENSORS
    // <Get Sensor Info>
    ipmi_register_callback(NETFUN_GRPEXT, dcmi::Commands::GET_SENSOR_INFO, NULL,
                           getSensorInfo, PRIVILEGE_OPERATOR);
#endif
    // <Get DCMI Configuration Parameters>
    ipmi_register_callback(NETFUN_GRPEXT, dcmi::Commands::GET_CONF_PARAMS, NULL,
                           getDCMIConfParams, PRIVILEGE_USER);

    // <Set DCMI Configuration Parameters>
    ipmi_register_callback(NETFUN_GRPEXT, dcmi::Commands::SET_CONF_PARAMS, NULL,
                           setDCMIConfParams, PRIVILEGE_ADMIN);

    return;
}
// 956379
