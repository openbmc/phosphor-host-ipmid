#pragma once

#include "nlohmann/json.hpp"

#include <sdbusplus/bus.hpp>

#include <map>
#include <string>
#include <vector>

namespace dcmi
{

using NumInstances = size_t;
using Json = nlohmann::json;

enum Commands
{
    SET_CONF_PARAMS = 0x12,
    GET_CONF_PARAMS = 0x13,
};

static constexpr auto propIntf = "org.freedesktop.DBus.Properties";
static constexpr auto assetTagIntf =
    "xyz.openbmc_project.Inventory.Decorator.AssetTag";
static constexpr auto assetTagProp = "AssetTag";
static constexpr auto networkServiceName = "xyz.openbmc_project.Network";
static constexpr auto networkConfigObj = "/xyz/openbmc_project/network/config";
static constexpr auto networkConfigIntf =
    "xyz.openbmc_project.Network.SystemConfiguration";
static constexpr auto hostNameProp = "HostName";
static constexpr auto temperatureSensorType = 0x01;
static constexpr size_t maxInstances = 255;
static constexpr uint8_t maxRecords = 8;
static constexpr auto gDCMISensorsConfig =
    "/usr/share/ipmi-providers/dcmi_sensors.json";
static constexpr auto ethernetIntf =
    "xyz.openbmc_project.Network.EthernetInterface";
static constexpr auto ethernetDefaultChannelNum = 0x1;
static constexpr auto networkRoot = "/xyz/openbmc_project/network";
static constexpr auto dhcpObj = "/xyz/openbmc_project/network/dhcp";
static constexpr auto dhcpIntf =
    "xyz.openbmc_project.Network.DHCPConfiguration";
static constexpr auto systemBusName = "org.freedesktop.systemd1";
static constexpr auto systemPath = "/org/freedesktop/systemd1";
static constexpr auto systemIntf = "org.freedesktop.systemd1.Manager";
static constexpr auto gDCMICapabilitiesConfig =
    "/usr/share/ipmi-providers/dcmi_cap.json";
static constexpr auto gDCMIPowerMgmtCapability = "PowerManagement";
static constexpr auto gDCMIPowerMgmtSupported = 0x1;
static constexpr auto gMaxSELEntriesMask = 0xFFF;
static constexpr auto gByteBitSize = 8;

static constexpr auto groupExtId = 0xDC;

/** @brief Check whether DCMI power management is supported
 *         in the DCMI Capabilities config file.
 *
 *  @return True if DCMI power management is supported
 */
bool isDCMIPowerMgmtSupported();

/** @brief Parse out JSON config file.
 *
 *  @param[in] configFile - JSON config file name
 *
 *  @return A json object
 */
Json parseJSONConfig(const std::string& configFile);

/**
 *  @brief Parameters for DCMI Configuration Parameters
 */
enum class DCMIConfigParameters : uint8_t
{
    ActivateDHCP = 1,
    DiscoveryConfig,
    DHCPTiming1,
    DHCPTiming2,
    DHCPTiming3,
};

/** @struct SetConfParamsRequest
 *
 *  DCMI Set DCMI Configuration Parameters Command.
 *  Refer DCMI specification Version 1.1 Section 6.1.2
 */
struct SetConfParamsRequest
{
    uint8_t paramSelect; //!< Parameter selector.
    uint8_t setSelect;   //!< Set Selector (use 00h for parameters that only
                         //!< have one set).
    uint8_t data[];      //!< Configuration parameter data.
} __attribute__((packed));

/** @struct GetConfParamsRequest
 *
 *  DCMI Get DCMI Configuration Parameters Command.
 *  Refer DCMI specification Version 1.1 Section 6.1.3
 */
struct GetConfParamsRequest
{
    uint8_t paramSelect; //!< Parameter selector.
    uint8_t setSelect;   //!< Set Selector. Selects a given set of parameters
                         //!< under a given Parameter selector value. 00h if
                         //!< parameter doesn't use a Set Selector.
} __attribute__((packed));

/** @struct GetConfParamsResponse
 *
 *  DCMI Get DCMI Configuration Parameters Command response.
 *  Refer DCMI specification Version 1.1 Section 6.1.3
 */
struct GetConfParamsResponse
{
    uint8_t major;         //!< DCMI Spec Conformance - major ver = 01h.
    uint8_t minor;         //!< DCMI Spec Conformance - minor ver = 05h.
    uint8_t paramRevision; //!< Parameter Revision = 01h.
    uint8_t data[];        //!< Parameter data.
} __attribute__((packed));

} // namespace dcmi
