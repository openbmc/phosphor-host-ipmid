#include "config.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <systemd/sd-bus.h>
#include <unistd.h>

#include <app/channel.hpp>
#include <app/watchdog.hpp>
#include <apphandler.hpp>
#include <ipmid/api.hpp>
#include <ipmid/sessiondef.hpp>
#include <ipmid/sessionhelper.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <nlohmann/json.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/message/types.hpp>
#include <sys_info_param.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/Control/Power/ACPIPowerState/server.hpp>
#include <xyz/openbmc_project/Software/Activation/server.hpp>
#include <xyz/openbmc_project/Software/Version/server.hpp>
#include <xyz/openbmc_project/State/BMC/server.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <regex>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

extern sd_bus* bus;

constexpr auto bmc_state_interface = "xyz.openbmc_project.State.BMC";
constexpr auto bmc_state_property = "CurrentBMCState";

static constexpr auto redundancyIntf =
    "xyz.openbmc_project.Software.RedundancyPriority";
static constexpr auto versionIntf = "xyz.openbmc_project.Software.Version";
static constexpr auto activationIntf =
    "xyz.openbmc_project.Software.Activation";
static constexpr auto softwareRoot = "/xyz/openbmc_project/software";

void register_netfn_app_functions() __attribute__((constructor));

using namespace phosphor::logging;
using namespace sdbusplus::error::xyz::openbmc_project::common;
using Version = sdbusplus::server::xyz::openbmc_project::software::Version;
using Activation =
    sdbusplus::server::xyz::openbmc_project::software::Activation;
using BMC = sdbusplus::server::xyz::openbmc_project::state::BMC;
namespace fs = std::filesystem;

#ifdef ENABLE_I2C_WHITELIST_CHECK
typedef struct
{
    uint8_t busId;
    uint8_t targetAddr;
    uint8_t targetAddrMask;
    std::vector<uint8_t> data;
    std::vector<uint8_t> dataMask;
} i2cControllerWRAllowlist;

static std::vector<i2cControllerWRAllowlist>& getWRAllowlist()
{
    static std::vector<i2cControllerWRAllowlist> wrAllowlist;
    return wrAllowlist;
}

static constexpr const char* i2cControllerWRAllowlistFile =
    "/usr/share/ipmi-providers/master_write_read_white_list.json";

static constexpr const char* filtersStr = "filters";
static constexpr const char* busIdStr = "busId";
static constexpr const char* targetAddrStr = "slaveAddr";
static constexpr const char* targetAddrMaskStr = "slaveAddrMask";
static constexpr const char* cmdStr = "command";
static constexpr const char* cmdMaskStr = "commandMask";
static constexpr int base_16 = 16;
#endif // ENABLE_I2C_WHITELIST_CHECK
static constexpr uint8_t oemCmdStart = 192;
static constexpr uint8_t invalidParamSelectorStart = 8;
static constexpr uint8_t invalidParamSelectorEnd = 191;

/**
 * @brief Returns the Version info from primary s/w object
 *
 * Get the Version info from the active s/w object which is having high
 * "Priority" value(a smaller number is a higher priority) and "Purpose"
 * is "BMC" from the list of all s/w objects those are implementing
 * RedundancyPriority interface from the given softwareRoot path.
 *
 * @return On success returns the Version info from primary s/w object.
 *
 */
std::string getActiveSoftwareVersionInfo(ipmi::Context::ptr ctx)
{
    std::string revision{};
    ipmi::ObjectTree objectTree;
    try
    {
        objectTree = ipmi::getAllDbusObjects(*ctx->bus, softwareRoot,
                                             redundancyIntf);
    }
    catch (const sdbusplus::exception_t& e)
    {
        log<level::ERR>("Failed to fetch redundancy object from dbus",
                        entry("INTERFACE=%s", redundancyIntf),
                        entry("ERRMSG=%s", e.what()));
        elog<InternalFailure>();
    }

    auto objectFound = false;
    for (auto& softObject : objectTree)
    {
        auto service = ipmi::getService(*ctx->bus, redundancyIntf,
                                        softObject.first);
        auto objValueTree = ipmi::getManagedObjects(*ctx->bus, service,
                                                    softwareRoot);

        auto minPriority = 0xFF;
        for (const auto& objIter : objValueTree)
        {
            try
            {
                auto& intfMap = objIter.second;
                auto& redundancyPriorityProps = intfMap.at(redundancyIntf);
                auto& versionProps = intfMap.at(versionIntf);
                auto& activationProps = intfMap.at(activationIntf);
                auto priority =
                    std::get<uint8_t>(redundancyPriorityProps.at("Priority"));
                auto purpose =
                    std::get<std::string>(versionProps.at("Purpose"));
                auto activation =
                    std::get<std::string>(activationProps.at("Activation"));
                auto version =
                    std::get<std::string>(versionProps.at("Version"));
                if ((Version::convertVersionPurposeFromString(purpose) ==
                     Version::VersionPurpose::BMC) &&
                    (Activation::convertActivationsFromString(activation) ==
                     Activation::Activations::Active))
                {
                    if (priority < minPriority)
                    {
                        minPriority = priority;
                        objectFound = true;
                        revision = std::move(version);
                    }
                }
            }
            catch (const std::exception& e)
            {
                log<level::ERR>(e.what());
            }
        }
    }

    if (!objectFound)
    {
        log<level::ERR>("Could not found an BMC software Object");
        elog<InternalFailure>();
    }

    return revision;
}

bool getCurrentBmcState()
{
    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};

    // Get the Inventory object implementing the BMC interface
    ipmi::DbusObjectInfo bmcObject = ipmi::getDbusObject(bus,
                                                         bmc_state_interface);
    auto variant = ipmi::getDbusProperty(bus, bmcObject.second, bmcObject.first,
                                         bmc_state_interface,
                                         bmc_state_property);

    return std::holds_alternative<std::string>(variant) &&
           BMC::convertBMCStateFromString(std::get<std::string>(variant)) ==
               BMC::BMCState::Ready;
}

bool getCurrentBmcStateWithFallback(const bool fallbackAvailability)
{
    try
    {
        return getCurrentBmcState();
    }
    catch (...)
    {
        // Nothing provided the BMC interface, therefore return whatever was
        // configured as the default.
        return fallbackAvailability;
    }
}

namespace acpi_state
{
using namespace sdbusplus::server::xyz::openbmc_project::control::power;

const static constexpr char* acpiObjPath =
    "/xyz/openbmc_project/control/host0/acpi_power_state";
const static constexpr char* acpiInterface =
    "xyz.openbmc_project.Control.Power.ACPIPowerState";
const static constexpr char* sysACPIProp = "SysACPIStatus";
const static constexpr char* devACPIProp = "DevACPIStatus";

enum class PowerStateType : uint8_t
{
    sysPowerState = 0x00,
    devPowerState = 0x01,
};

// Defined in 20.6 of ipmi doc
enum class PowerState : uint8_t
{
    s0G0D0 = 0x00,
    s1D1 = 0x01,
    s2D2 = 0x02,
    s3D3 = 0x03,
    s4 = 0x04,
    s5G2 = 0x05,
    s4S5 = 0x06,
    g3 = 0x07,
    sleep = 0x08,
    g1Sleep = 0x09,
    override = 0x0a,
    legacyOn = 0x20,
    legacyOff = 0x21,
    unknown = 0x2a,
    noChange = 0x7f,
};

static constexpr uint8_t stateChanged = 0x80;

std::map<ACPIPowerState::ACPI, PowerState> dbusToIPMI = {
    {ACPIPowerState::ACPI::S0_G0_D0, PowerState::s0G0D0},
    {ACPIPowerState::ACPI::S1_D1, PowerState::s1D1},
    {ACPIPowerState::ACPI::S2_D2, PowerState::s2D2},
    {ACPIPowerState::ACPI::S3_D3, PowerState::s3D3},
    {ACPIPowerState::ACPI::S4, PowerState::s4},
    {ACPIPowerState::ACPI::S5_G2, PowerState::s5G2},
    {ACPIPowerState::ACPI::S4_S5, PowerState::s4S5},
    {ACPIPowerState::ACPI::G3, PowerState::g3},
    {ACPIPowerState::ACPI::SLEEP, PowerState::sleep},
    {ACPIPowerState::ACPI::G1_SLEEP, PowerState::g1Sleep},
    {ACPIPowerState::ACPI::OVERRIDE, PowerState::override},
    {ACPIPowerState::ACPI::LEGACY_ON, PowerState::legacyOn},
    {ACPIPowerState::ACPI::LEGACY_OFF, PowerState::legacyOff},
    {ACPIPowerState::ACPI::Unknown, PowerState::unknown}};

bool isValidACPIState(acpi_state::PowerStateType type, uint8_t state)
{
    if (type == acpi_state::PowerStateType::sysPowerState)
    {
        if ((state <= static_cast<uint8_t>(acpi_state::PowerState::override)) ||
            (state == static_cast<uint8_t>(acpi_state::PowerState::legacyOn)) ||
            (state ==
             static_cast<uint8_t>(acpi_state::PowerState::legacyOff)) ||
            (state == static_cast<uint8_t>(acpi_state::PowerState::unknown)) ||
            (state == static_cast<uint8_t>(acpi_state::PowerState::noChange)))
        {
            return true;
        }
        else
        {
            return false;
        }
    }
    else if (type == acpi_state::PowerStateType::devPowerState)
    {
        if ((state <= static_cast<uint8_t>(acpi_state::PowerState::s3D3)) ||
            (state == static_cast<uint8_t>(acpi_state::PowerState::unknown)) ||
            (state == static_cast<uint8_t>(acpi_state::PowerState::noChange)))
        {
            return true;
        }
        else
        {
            return false;
        }
    }
    else
    {
        return false;
    }
    return false;
}
} // namespace acpi_state

/** @brief implements Set ACPI Power State command
 * @param sysAcpiState - ACPI system power state to set
 * @param devAcpiState - ACPI device power state to set
 *
 * @return IPMI completion code on success
 **/
ipmi::RspType<> ipmiSetAcpiPowerState(uint8_t sysAcpiState,
                                      uint8_t devAcpiState)
{
    auto s = static_cast<uint8_t>(acpi_state::PowerState::unknown);

    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};

    auto value = acpi_state::ACPIPowerState::ACPI::Unknown;

    if (sysAcpiState & acpi_state::stateChanged)
    {
        // set system power state
        s = sysAcpiState & ~acpi_state::stateChanged;

        if (!acpi_state::isValidACPIState(
                acpi_state::PowerStateType::sysPowerState, s))
        {
            log<level::ERR>("set_acpi_power sys invalid input",
                            entry("S=%x", s));
            return ipmi::responseParmOutOfRange();
        }

        // valid input
        if (s == static_cast<uint8_t>(acpi_state::PowerState::noChange))
        {
            log<level::DEBUG>("No change for system power state");
        }
        else
        {
            auto found = std::find_if(acpi_state::dbusToIPMI.begin(),
                                      acpi_state::dbusToIPMI.end(),
                                      [&s](const auto& iter) {
                return (static_cast<uint8_t>(iter.second) == s);
            });

            value = found->first;

            try
            {
                auto acpiObject =
                    ipmi::getDbusObject(bus, acpi_state::acpiInterface);
                ipmi::setDbusProperty(bus, acpiObject.second, acpiObject.first,
                                      acpi_state::acpiInterface,
                                      acpi_state::sysACPIProp,
                                      convertForMessage(value));
            }
            catch (const InternalFailure& e)
            {
                log<level::ERR>("Failed in set ACPI system property",
                                entry("EXCEPTION=%s", e.what()));
                return ipmi::responseUnspecifiedError();
            }
        }
    }
    else
    {
        log<level::DEBUG>("Do not change system power state");
    }

    if (devAcpiState & acpi_state::stateChanged)
    {
        // set device power state
        s = devAcpiState & ~acpi_state::stateChanged;
        if (!acpi_state::isValidACPIState(
                acpi_state::PowerStateType::devPowerState, s))
        {
            log<level::ERR>("set_acpi_power dev invalid input",
                            entry("S=%x", s));
            return ipmi::responseParmOutOfRange();
        }

        // valid input
        if (s == static_cast<uint8_t>(acpi_state::PowerState::noChange))
        {
            log<level::DEBUG>("No change for device power state");
        }
        else
        {
            auto found = std::find_if(acpi_state::dbusToIPMI.begin(),
                                      acpi_state::dbusToIPMI.end(),
                                      [&s](const auto& iter) {
                return (static_cast<uint8_t>(iter.second) == s);
            });

            value = found->first;

            try
            {
                auto acpiObject =
                    ipmi::getDbusObject(bus, acpi_state::acpiInterface);
                ipmi::setDbusProperty(bus, acpiObject.second, acpiObject.first,
                                      acpi_state::acpiInterface,
                                      acpi_state::devACPIProp,
                                      convertForMessage(value));
            }
            catch (const InternalFailure& e)
            {
                log<level::ERR>("Failed in set ACPI device property",
                                entry("EXCEPTION=%s", e.what()));
                return ipmi::responseUnspecifiedError();
            }
        }
    }
    else
    {
        log<level::DEBUG>("Do not change device power state");
    }
    return ipmi::responseSuccess();
}

/**
 *  @brief implements the get ACPI power state command
 *
 *  @return IPMI completion code plus response data on success.
 *   -  ACPI system power state
 *   -  ACPI device power state
 **/
ipmi::RspType<uint8_t, // acpiSystemPowerState
              uint8_t  // acpiDevicePowerState
              >
    ipmiGetAcpiPowerState()
{
    uint8_t sysAcpiState;
    uint8_t devAcpiState;

    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};

    try
    {
        auto acpiObject = ipmi::getDbusObject(bus, acpi_state::acpiInterface);

        auto sysACPIVal = ipmi::getDbusProperty(
            bus, acpiObject.second, acpiObject.first, acpi_state::acpiInterface,
            acpi_state::sysACPIProp);
        auto sysACPI = acpi_state::ACPIPowerState::convertACPIFromString(
            std::get<std::string>(sysACPIVal));
        sysAcpiState = static_cast<uint8_t>(acpi_state::dbusToIPMI.at(sysACPI));

        auto devACPIVal = ipmi::getDbusProperty(
            bus, acpiObject.second, acpiObject.first, acpi_state::acpiInterface,
            acpi_state::devACPIProp);
        auto devACPI = acpi_state::ACPIPowerState::convertACPIFromString(
            std::get<std::string>(devACPIVal));
        devAcpiState = static_cast<uint8_t>(acpi_state::dbusToIPMI.at(devACPI));
    }
    catch (const InternalFailure& e)
    {
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(sysAcpiState, devAcpiState);
}

typedef struct
{
    char major;
    char minor;
    uint8_t aux[4];
} Revision;

/* Use regular expression searching matched pattern X.Y, and convert it to  */
/* Major (X) and Minor (Y) version.                                         */
/* Example:                                                                 */
/* version = 2.14.0-dev                                                     */
/*           ^ ^                                                            */
/*           | |---------------- Minor                                      */
/*           |------------------ Major                                      */
/*                                                                          */
/* Default regex string only tries to match Major and Minor version.        */
/*                                                                          */
/* To match more firmware version info, platforms need to define it own     */
/* regex string to match more strings, and assign correct mapping index in  */
/* matches array.                                                           */
/*                                                                          */
/* matches[0]: matched index for major ver                                  */
/* matches[1]: matched index for minor ver                                  */
/* matches[2]: matched index for aux[0] (set 0 to skip)                     */
/* matches[3]: matched index for aux[1] (set 0 to skip)                     */
/* matches[4]: matched index for aux[2] (set 0 to skip)                     */
/* matches[5]: matched index for aux[3] (set 0 to skip)                     */
/* Example:                                                                 */
/* regex = "([\d]+).([\d]+).([\d]+)-dev-([\d]+)-g([0-9a-fA-F]{2})           */
/*          ([0-9a-fA-F]{2})([0-9a-fA-F]{2})([0-9a-fA-F]{2})"               */
/* matches = {1,2,5,6,7,8}                                                  */
/* version = 2.14.0-dev-750-g37a7c5ad1-dirty                                */
/*           ^ ^  ^     ^    ^ ^ ^ ^                                        */
/*           | |  |     |    | | | |                                        */
/*           | |  |     |    | | | |-- Aux byte 3 (0xAD), index 8           */
/*           | |  |     |    | | |---- Aux byte 2 (0xC5), index 7           */
/*           | |  |     |    | |------ Aux byte 1 (0xA7), index 6           */
/*           | |  |     |    |-------- Aux byte 0 (0x37), index 5           */
/*           | |  |     |------------- Not used, index 4                    */
/*           | |  |------------------- Not used, index 3                    */
/*           | |---------------------- Minor (14), index 2                  */
/*           |------------------------ Major (2), index 1                   */
int convertVersion(std::string s, Revision& rev)
{
    static const std::vector<size_t> matches = {
        MAJOR_MATCH_INDEX, MINOR_MATCH_INDEX, AUX_0_MATCH_INDEX,
        AUX_1_MATCH_INDEX, AUX_2_MATCH_INDEX, AUX_3_MATCH_INDEX};
    std::regex fw_regex(FW_VER_REGEX);
    std::smatch m;
    Revision r = {0};
    size_t val;

    if (std::regex_search(s, m, fw_regex))
    {
        if (m.size() < *std::max_element(matches.begin(), matches.end()))
        { // max index higher than match count
            return -1;
        }

        // convert major
        {
            std::string_view str = m[matches[0]].str();
            auto [ptr, ec]{std::from_chars(str.begin(), str.end(), val)};
            if (ec != std::errc() || ptr != str.begin() + str.size())
            { // failed to convert major string
                return -1;
            }

            if (val >= 2000)
            { // For the platforms use year as major version, it would expect to
              // have major version between 0 - 99. If the major version is
              // greater than or equal to 2000, it is treated as a year and
              // converted to 0 - 99.
                r.major = val % 100;
            }
            else
            {
                r.major = val & 0x7F;
            }
        }

        // convert minor
        {
            std::string_view str = m[matches[1]].str();
            auto [ptr, ec]{std::from_chars(str.begin(), str.end(), val)};
            if (ec != std::errc() || ptr != str.begin() + str.size())
            { // failed to convert minor string
                return -1;
            }
            r.minor = val & 0xFF;
        }

        // convert aux bytes
        {
            size_t i;
            for (i = 0; i < 4; i++)
            {
                if (matches[i + 2] == 0)
                {
                    continue;
                }

                std::string_view str = m[matches[i + 2]].str();
                auto [ptr,
                      ec]{std::from_chars(str.begin(), str.end(), val, 16)};
                if (ec != std::errc() || ptr != str.begin() + str.size())
                { // failed to convert aux byte string
                    break;
                }

                r.aux[i] = val & 0xFF;
            }

            if (i != 4)
            { // something wrong durign converting aux bytes
                return -1;
            }
        }

        // all matched
        rev = r;
        return 0;
    }

    return -1;
}

/* @brief: Implement the Get Device ID IPMI command per the IPMI spec
 *  @param[in] ctx - shared_ptr to an IPMI context struct
 *
 *  @returns IPMI completion code plus response data
 *   - Device ID (manufacturer defined)
 *   - Device revision[4 bits]; reserved[3 bits]; SDR support[1 bit]
 *   - FW revision major[7 bits] (binary encoded); available[1 bit]
 *   - FW Revision minor (BCD encoded)
 *   - IPMI version (0x02 for IPMI 2.0)
 *   - device support (bitfield of supported options)
 *   - MFG IANA ID (3 bytes)
 *   - product ID (2 bytes)
 *   - AUX info (4 bytes)
 */
ipmi::RspType<uint8_t,  // Device ID
              uint8_t,  // Device Revision
              uint8_t,  // Firmware Revision Major
              uint8_t,  // Firmware Revision minor
              uint8_t,  // IPMI version
              uint8_t,  // Additional device support
              uint24_t, // MFG ID
              uint16_t, // Product ID
              uint32_t  // AUX info
              >
    ipmiAppGetDeviceId([[maybe_unused]] ipmi::Context::ptr ctx)
{
    static struct
    {
        uint8_t id;
        uint8_t revision;
        uint8_t fw[2];
        uint8_t ipmiVer;
        uint8_t addnDevSupport;
        uint24_t manufId;
        uint16_t prodId;
        uint32_t aux;
    } devId;
    static bool dev_id_initialized = false;
    static bool defaultActivationSetting = true;
    const char* filename = "/usr/share/ipmi-providers/dev_id.json";
    constexpr auto ipmiDevIdStateShift = 7;
    constexpr auto ipmiDevIdFw1Mask = ~(1 << ipmiDevIdStateShift);

#ifdef GET_DBUS_ACTIVE_SOFTWARE
    static bool haveBMCVersion = false;
    if (!haveBMCVersion || !dev_id_initialized)
    {
        int r = -1;
        Revision rev = {0, 0, 0, 0};
        try
        {
            auto version = getActiveSoftwareVersionInfo(ctx);
            r = convertVersion(version, rev);
        }
        catch (const std::exception& e)
        {
            log<level::ERR>(e.what());
        }

        if (r >= 0)
        {
            // bit7 identifies if the device is available
            // 0=normal operation
            // 1=device firmware, SDR update,
            // or self-initialization in progress.
            // The availability may change in run time, so mask here
            // and initialize later.
            devId.fw[0] = rev.major & ipmiDevIdFw1Mask;

            rev.minor = (rev.minor > 99 ? 99 : rev.minor);
            devId.fw[1] = rev.minor % 10 + (rev.minor / 10) * 16;
            std::memcpy(&devId.aux, rev.aux, sizeof(rev.aux));
            haveBMCVersion = true;
        }
    }
#endif
    if (!dev_id_initialized)
    {
        // IPMI Spec version 2.0
        devId.ipmiVer = 2;

        std::ifstream devIdFile(filename);
        if (devIdFile.is_open())
        {
            auto data = nlohmann::json::parse(devIdFile, nullptr, false);
            if (!data.is_discarded())
            {
                devId.id = data.value("id", 0);
                devId.revision = data.value("revision", 0);
                devId.addnDevSupport = data.value("addn_dev_support", 0);
                devId.manufId = data.value("manuf_id", 0);
                devId.prodId = data.value("prod_id", 0);
#ifdef GET_DBUS_ACTIVE_SOFTWARE
                if (!(AUX_0_MATCH_INDEX || AUX_1_MATCH_INDEX ||
                      AUX_2_MATCH_INDEX || AUX_3_MATCH_INDEX))
#endif
                {
                    devId.aux = data.value("aux", 0);
                }

                if (data.contains("firmware_revision"))
                {
                    const auto& firmwareRevision = data.at("firmware_revision");
                    if (firmwareRevision.contains("major"))
                    {
                        firmwareRevision.at("major").get_to(devId.fw[0]);
                    }
                    if (firmwareRevision.contains("minor"))
                    {
                        firmwareRevision.at("minor").get_to(devId.fw[1]);
                    }
                }

                // Set the availablitity of the BMC.
                defaultActivationSetting = data.value("availability", true);

                // Don't read the file every time if successful
                dev_id_initialized = true;
            }
            else
            {
                log<level::ERR>("Device ID JSON parser failure");
                return ipmi::responseUnspecifiedError();
            }
        }
        else
        {
            log<level::ERR>("Device ID file not found");
            return ipmi::responseUnspecifiedError();
        }
    }

    // Set availability to the actual current BMC state
    devId.fw[0] &= ipmiDevIdFw1Mask;
    if (!getCurrentBmcStateWithFallback(defaultActivationSetting))
    {
        devId.fw[0] |= (1 << ipmiDevIdStateShift);
    }

    return ipmi::responseSuccess(
        devId.id, devId.revision, devId.fw[0], devId.fw[1], devId.ipmiVer,
        devId.addnDevSupport, devId.manufId, devId.prodId, devId.aux);
}

auto ipmiAppGetSelfTestResults() -> ipmi::RspType<uint8_t, uint8_t>
{
    // Byte 2:
    //  55h - No error.
    //  56h - Self Test function not implemented in this controller.
    //  57h - Corrupted or inaccesssible data or devices.
    //  58h - Fatal hardware error.
    //  FFh - reserved.
    //  all other: Device-specific 'internal failure'.
    //  Byte 3:
    //      For byte 2 = 55h, 56h, FFh:     00h
    //      For byte 2 = 58h, all other:    Device-specific
    //      For byte 2 = 57h:   self-test error bitfield.
    //      Note: returning 57h does not imply that all test were run.
    //      [7] 1b = Cannot access SEL device.
    //      [6] 1b = Cannot access SDR Repository.
    //      [5] 1b = Cannot access BMC FRU device.
    //      [4] 1b = IPMB signal lines do not respond.
    //      [3] 1b = SDR Repository empty.
    //      [2] 1b = Internal Use Area of BMC FRU corrupted.
    //      [1] 1b = controller update 'boot block' firmware corrupted.
    //      [0] 1b = controller operational firmware corrupted.
    constexpr uint8_t notImplemented = 0x56;
    constexpr uint8_t zero = 0;
    return ipmi::responseSuccess(notImplemented, zero);
}

static constexpr size_t uuidBinaryLength = 16;
static std::array<uint8_t, uuidBinaryLength> rfc4122ToIpmi(std::string rfc4122)
{
    using Argument = xyz::openbmc_project::common::InvalidArgument;
    // UUID is in RFC4122 format. Ex: 61a39523-78f2-11e5-9862-e6402cfc3223
    // Per IPMI Spec 2.0 need to convert to 16 hex bytes and reverse the byte
    // order
    // Ex: 0x2332fc2c40e66298e511f2782395a361
    constexpr size_t uuidHexLength = (2 * uuidBinaryLength);
    constexpr size_t uuidRfc4122Length = (uuidHexLength + 4);
    std::array<uint8_t, uuidBinaryLength> uuid;
    if (rfc4122.size() == uuidRfc4122Length)
    {
        rfc4122.erase(std::remove(rfc4122.begin(), rfc4122.end(), '-'),
                      rfc4122.end());
    }
    if (rfc4122.size() != uuidHexLength)
    {
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("rfc4122"),
                              Argument::ARGUMENT_VALUE(rfc4122.c_str()));
    }
    for (size_t ind = 0; ind < uuidHexLength; ind += 2)
    {
        char v[3];
        v[0] = rfc4122[ind];
        v[1] = rfc4122[ind + 1];
        v[2] = 0;
        size_t err;
        long b;
        try
        {
            b = std::stoul(v, &err, 16);
        }
        catch (const std::exception& e)
        {
            elog<InvalidArgument>(Argument::ARGUMENT_NAME("rfc4122"),
                                  Argument::ARGUMENT_VALUE(rfc4122.c_str()));
        }
        // check that exactly two ascii bytes were converted
        if (err != 2)
        {
            elog<InvalidArgument>(Argument::ARGUMENT_NAME("rfc4122"),
                                  Argument::ARGUMENT_VALUE(rfc4122.c_str()));
        }
        uuid[uuidBinaryLength - (ind / 2) - 1] = static_cast<uint8_t>(b);
    }
    return uuid;
}

auto ipmiAppGetDeviceGuid()
    -> ipmi::RspType<std::array<uint8_t, uuidBinaryLength>>
{
    // return a fixed GUID based on /etc/machine-id
    // This should match the /redfish/v1/Managers/bmc's UUID data

    // machine specific application ID (for BMC ID)
    // generated by systemd-id128 -p new as per man page
    static constexpr sd_id128_t bmcUuidAppId = SD_ID128_MAKE(
        e0, e1, 73, 76, 64, 61, 47, da, a5, 0c, d0, cc, 64, 12, 45, 78);

    sd_id128_t bmcUuid;
    // create the UUID from /etc/machine-id via the systemd API
    sd_id128_get_machine_app_specific(bmcUuidAppId, &bmcUuid);

    char bmcUuidCstr[SD_ID128_STRING_MAX];
    std::string systemUuid = sd_id128_to_string(bmcUuid, bmcUuidCstr);

    std::array<uint8_t, uuidBinaryLength> uuid = rfc4122ToIpmi(systemUuid);
    return ipmi::responseSuccess(uuid);
}

auto ipmiAppGetBtCapabilities()
    -> ipmi::RspType<uint8_t, uint8_t, uint8_t, uint8_t, uint8_t>
{
    // Per IPMI 2.0 spec, the input and output buffer size must be the max
    // buffer size minus one byte to allocate space for the length byte.
    constexpr uint8_t nrOutstanding = 0x01;
    constexpr uint8_t inputBufferSize = MAX_IPMI_BUFFER - 1;
    constexpr uint8_t outputBufferSize = MAX_IPMI_BUFFER - 1;
    constexpr uint8_t transactionTime = 0x0A;
    constexpr uint8_t nrRetries = 0x01;

    return ipmi::responseSuccess(nrOutstanding, inputBufferSize,
                                 outputBufferSize, transactionTime, nrRetries);
}

auto ipmiAppGetSystemGuid(ipmi::Context::ptr& ctx)
    -> ipmi::RspType<std::array<uint8_t, 16>>
{
    static constexpr auto uuidInterface = "xyz.openbmc_project.Common.UUID";
    static constexpr auto uuidProperty = "UUID";

    // Get the Inventory object implementing BMC interface
    ipmi::DbusObjectInfo objectInfo{};
    boost::system::error_code ec = ipmi::getDbusObject(ctx, uuidInterface,
                                                       objectInfo);
    if (ec.value())
    {
        log<level::ERR>("Failed to locate System UUID object",
                        entry("INTERFACE=%s", uuidInterface),
                        entry("ERROR=%s", ec.message().c_str()));
        return ipmi::responseUnspecifiedError();
    }

    // Read UUID property value from bmcObject
    // UUID is in RFC4122 format Ex: 61a39523-78f2-11e5-9862-e6402cfc3223
    std::string rfc4122Uuid{};
    ec = ipmi::getDbusProperty(ctx, objectInfo.second, objectInfo.first,
                               uuidInterface, uuidProperty, rfc4122Uuid);
    if (ec.value())
    {
        log<level::ERR>("Failed in reading BMC UUID property",
                        entry("INTERFACE=%s", uuidInterface),
                        entry("PROPERTY=%s", uuidProperty),
                        entry("ERROR=%s", ec.message().c_str()));
        return ipmi::responseUnspecifiedError();
    }
    std::array<uint8_t, 16> uuid;
    try
    {
        // convert to IPMI format
        uuid = rfc4122ToIpmi(rfc4122Uuid);
    }
    catch (const InvalidArgument& e)
    {
        log<level::ERR>("Failed in parsing BMC UUID property",
                        entry("INTERFACE=%s", uuidInterface),
                        entry("PROPERTY=%s", uuidProperty),
                        entry("VALUE=%s", rfc4122Uuid.c_str()));
        return ipmi::responseUnspecifiedError();
    }
    return ipmi::responseSuccess(uuid);
}

/**
 * @brief set the session state as teardown
 *
 * This function is to set the session state to tear down in progress if the
 * state is active.
 *
 * @param[in] busp - Dbus obj
 * @param[in] service - service name
 * @param[in] obj - object path
 *
 * @return success completion code if it sets the session state to
 * tearDownInProgress else return the corresponding error completion code.
 **/
uint8_t setSessionState(std::shared_ptr<sdbusplus::asio::connection>& busp,
                        const std::string& service, const std::string& obj)
{
    try
    {
        uint8_t sessionState = std::get<uint8_t>(ipmi::getDbusProperty(
            *busp, service, obj, session::sessionIntf, "State"));

        if (sessionState == static_cast<uint8_t>(session::State::active))
        {
            ipmi::setDbusProperty(
                *busp, service, obj, session::sessionIntf, "State",
                static_cast<uint8_t>(session::State::tearDownInProgress));
            return ipmi::ccSuccess;
        }
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("Failed in getting session state property",
                        entry("service=%s", service.c_str()),
                        entry("object path=%s", obj.c_str()),
                        entry("interface=%s", session::sessionIntf));
        return ipmi::ccUnspecifiedError;
    }

    return ipmi::ccInvalidFieldRequest;
}

ipmi::RspType<> ipmiAppCloseSession(uint32_t reqSessionId,
                                    std::optional<uint8_t> requestSessionHandle)
{
    auto busp = getSdBus();
    uint8_t reqSessionHandle =
        requestSessionHandle.value_or(session::defaultSessionHandle);

    if (reqSessionId == session::sessionZero &&
        reqSessionHandle == session::defaultSessionHandle)
    {
        return ipmi::response(session::ccInvalidSessionId);
    }

    if (reqSessionId == session::sessionZero &&
        reqSessionHandle == session::invalidSessionHandle)
    {
        return ipmi::response(session::ccInvalidSessionHandle);
    }

    if (reqSessionId != session::sessionZero &&
        reqSessionHandle != session::defaultSessionHandle)
    {
        return ipmi::response(ipmi::ccInvalidFieldRequest);
    }

    try
    {
        ipmi::ObjectTree objectTree = ipmi::getAllDbusObjects(
            *busp, session::sessionManagerRootPath, session::sessionIntf);

        for (auto& objectTreeItr : objectTree)
        {
            const std::string obj = objectTreeItr.first;

            if (isSessionObjectMatched(obj, reqSessionId, reqSessionHandle))
            {
                auto& serviceMap = objectTreeItr.second;

                // Session id and session handle are unique for each session.
                // Session id and handler are retrived from the object path and
                // object path will be unique for each session. Checking if
                // multiple objects exist with same object path under multiple
                // services.
                if (serviceMap.size() != 1)
                {
                    return ipmi::responseUnspecifiedError();
                }

                auto itr = serviceMap.begin();
                const std::string service = itr->first;
                return ipmi::response(setSessionState(busp, service, obj));
            }
        }
    }
    catch (const sdbusplus::exception_t& e)
    {
        log<level::ERR>("Failed to fetch object from dbus",
                        entry("INTERFACE=%s", session::sessionIntf),
                        entry("ERRMSG=%s", e.what()));
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseInvalidFieldRequest();
}

uint8_t getTotalSessionCount()
{
    uint8_t count = 0, ch = 0;

    while (ch < ipmi::maxIpmiChannels &&
           count < session::maxNetworkInstanceSupported)
    {
        ipmi::ChannelInfo chInfo{};
        ipmi::getChannelInfo(ch, chInfo);
        if (static_cast<ipmi::EChannelMediumType>(chInfo.mediumType) ==
            ipmi::EChannelMediumType::lan8032)
        {
            count++;
        }
        ch++;
    }
    return count * session::maxSessionCountPerChannel;
}

/**
 * @brief get session info request data.
 *
 * This function validates the request data and retrive request session id,
 * session handle.
 *
 * @param[in] ctx - context of current session.
 * @param[in] sessionIndex - request session index
 * @param[in] payload - input payload
 * @param[in] reqSessionId - unpacked session Id will be asigned
 * @param[in] reqSessionHandle - unpacked session handle will be asigned
 *
 * @return success completion code if request data is valid
 * else return the correcponding error completion code.
 **/
uint8_t getSessionInfoRequestData(const ipmi::Context::ptr ctx,
                                  const uint8_t sessionIndex,
                                  ipmi::message::Payload& payload,
                                  uint32_t& reqSessionId,
                                  uint8_t& reqSessionHandle)
{
    if ((sessionIndex > session::maxSessionCountPerChannel) &&
        (sessionIndex < session::searchSessionByHandle))
    {
        return ipmi::ccInvalidFieldRequest;
    }

    switch (sessionIndex)
    {
        case session::searchCurrentSession:

            ipmi::ChannelInfo chInfo;
            ipmi::getChannelInfo(ctx->channel, chInfo);

            if (static_cast<ipmi::EChannelMediumType>(chInfo.mediumType) !=
                ipmi::EChannelMediumType::lan8032)
            {
                return ipmi::ccInvalidFieldRequest;
            }

            if (!payload.fullyUnpacked())
            {
                return ipmi::ccReqDataLenInvalid;
            }
            // Check if current sessionId is 0, sessionId 0 is reserved.
            if (ctx->sessionId == session::sessionZero)
            {
                return session::ccInvalidSessionId;
            }
            reqSessionId = ctx->sessionId;
            break;

        case session::searchSessionByHandle:

            if ((payload.unpack(reqSessionHandle)) ||
                (!payload.fullyUnpacked()))
            {
                return ipmi::ccReqDataLenInvalid;
            }

            if ((reqSessionHandle == session::sessionZero) ||
                ((reqSessionHandle & session::multiIntfaceSessionHandleMask) >
                 session::maxSessionCountPerChannel))
            {
                return session::ccInvalidSessionHandle;
            }
            break;

        case session::searchSessionById:

            if ((payload.unpack(reqSessionId)) || (!payload.fullyUnpacked()))
            {
                return ipmi::ccReqDataLenInvalid;
            }

            if (reqSessionId == session::sessionZero)
            {
                return session::ccInvalidSessionId;
            }
            break;

        default:
            if (!payload.fullyUnpacked())
            {
                return ipmi::ccReqDataLenInvalid;
            }
            break;
    }
    return ipmi::ccSuccess;
}

uint8_t getSessionState(ipmi::Context::ptr ctx, const std::string& service,
                        const std::string& objPath, uint8_t& sessionState)
{
    boost::system::error_code ec = ipmi::getDbusProperty(
        ctx, service, objPath, session::sessionIntf, "State", sessionState);
    if (ec)
    {
        log<level::ERR>("Failed to fetch state property ",
                        entry("SERVICE=%s", service.c_str()),
                        entry("OBJECTPATH=%s", objPath.c_str()),
                        entry("INTERFACE=%s", session::sessionIntf),
                        entry("ERRMSG=%s", ec.message().c_str()));
        return ipmi::ccUnspecifiedError;
    }
    return ipmi::ccSuccess;
}

static constexpr uint8_t macAddrLen = 6;
/** Alias SessionDetails - contain the optional information about an
 *        RMCP+ session.
 *
 *  @param userID - uint6_t session user ID (0-63)
 *  @param reserved - uint2_t reserved
 *  @param privilege - uint4_t session privilege (0-5)
 *  @param reserved - uint4_t reserved
 *  @param channel - uint4_t session channel number
 *  @param protocol - uint4_t session protocol
 *  @param remoteIP - uint32_t remote IP address
 *  @param macAddr - std::array<uint8_t, 6> mac address
 *  @param port - uint16_t remote port
 */
using SessionDetails =
    std::tuple<uint2_t, uint6_t, uint4_t, uint4_t, uint4_t, uint4_t, uint32_t,
               std::array<uint8_t, macAddrLen>, uint16_t>;

/** @brief get session details for a given session
 *
 *  @param[in] ctx - ipmi::Context pointer for accessing D-Bus
 *  @param[in] service - D-Bus service name to fetch details from
 *  @param[in] objPath - D-Bus object path for session
 *  @param[out] sessionHandle - return session handle for session
 *  @param[out] sessionState - return session state for session
 *  @param[out] details - return a SessionDetails tuple containing other
 *                        session info
 *  @return - ipmi::Cc success or error code
 */
ipmi::Cc getSessionDetails(ipmi::Context::ptr ctx, const std::string& service,
                           const std::string& objPath, uint8_t& sessionHandle,
                           uint8_t& sessionState, SessionDetails& details)
{
    ipmi::PropertyMap sessionProps;
    boost::system::error_code ec = ipmi::getAllDbusProperties(
        ctx, service, objPath, session::sessionIntf, sessionProps);

    if (ec)
    {
        log<level::ERR>("Failed to fetch state property ",
                        entry("SERVICE=%s", service.c_str()),
                        entry("OBJECTPATH=%s", objPath.c_str()),
                        entry("INTERFACE=%s", session::sessionIntf),
                        entry("ERRMSG=%s", ec.message().c_str()));
        return ipmi::ccUnspecifiedError;
    }

    sessionState = ipmi::mappedVariant<uint8_t>(
        sessionProps, "State", static_cast<uint8_t>(session::State::inactive));
    if (sessionState == static_cast<uint8_t>(session::State::active))
    {
        sessionHandle = ipmi::mappedVariant<uint8_t>(sessionProps,
                                                     "SessionHandle", 0);
        std::get<0>(details) = ipmi::mappedVariant<uint8_t>(sessionProps,
                                                            "UserID", 0xff);
        // std::get<1>(details) = 0; // (default constructed to 0)
        std::get<2>(details) =
            ipmi::mappedVariant<uint8_t>(sessionProps, "CurrentPrivilege", 0);
        // std::get<3>(details) = 0; // (default constructed to 0)
        std::get<4>(details) = ipmi::mappedVariant<uint8_t>(sessionProps,
                                                            "ChannelNum", 0xff);
        constexpr uint4_t rmcpPlusProtocol = 1;
        std::get<5>(details) = rmcpPlusProtocol;
        std::get<6>(details) = ipmi::mappedVariant<uint32_t>(sessionProps,
                                                             "RemoteIPAddr", 0);
        // std::get<7>(details) = {{0}}; // default constructed to all 0
        std::get<8>(details) = ipmi::mappedVariant<uint16_t>(sessionProps,
                                                             "RemotePort", 0);
    }

    return ipmi::ccSuccess;
}

ipmi::RspType<uint8_t, // session handle,
              uint8_t, // total session count
              uint8_t, // active session count
              std::optional<SessionDetails>>
    ipmiAppGetSessionInfo(ipmi::Context::ptr ctx, uint8_t sessionIndex,
                          ipmi::message::Payload& payload)
{
    uint32_t reqSessionId = 0;
    uint8_t reqSessionHandle = session::defaultSessionHandle;
    // initializing state to 0xff as 0 represents state as inactive.
    uint8_t state = 0xFF;

    uint8_t completionCode = getSessionInfoRequestData(
        ctx, sessionIndex, payload, reqSessionId, reqSessionHandle);

    if (completionCode)
    {
        return ipmi::response(completionCode);
    }
    ipmi::ObjectTree objectTree;
    boost::system::error_code ec = ipmi::getAllDbusObjects(
        ctx, session::sessionManagerRootPath, session::sessionIntf, objectTree);
    if (ec)
    {
        log<level::ERR>("Failed to fetch object from dbus",
                        entry("INTERFACE=%s", session::sessionIntf),
                        entry("ERRMSG=%s", ec.message().c_str()));
        return ipmi::responseUnspecifiedError();
    }

    uint8_t totalSessionCount = getTotalSessionCount();
    uint8_t activeSessionCount = 0;
    uint8_t sessionHandle = session::defaultSessionHandle;
    uint8_t activeSessionHandle = 0;
    std::optional<SessionDetails> maybeDetails;
    uint8_t index = 0;
    for (auto& objectTreeItr : objectTree)
    {
        uint32_t sessionId = 0;
        std::string objectPath = objectTreeItr.first;

        if (!parseCloseSessionInputPayload(objectPath, sessionId,
                                           sessionHandle))
        {
            continue;
        }
        index++;
        auto& serviceMap = objectTreeItr.second;
        auto itr = serviceMap.begin();

        if (serviceMap.size() != 1)
        {
            return ipmi::responseUnspecifiedError();
        }

        std::string service = itr->first;
        uint8_t sessionState = 0;
        completionCode = getSessionState(ctx, service, objectPath,
                                         sessionState);
        if (completionCode)
        {
            return ipmi::response(completionCode);
        }

        if (sessionState == static_cast<uint8_t>(session::State::active))
        {
            activeSessionCount++;
        }

        if (index == sessionIndex || reqSessionId == sessionId ||
            reqSessionHandle == sessionHandle)
        {
            SessionDetails details{};
            completionCode = getSessionDetails(ctx, service, objectPath,
                                               sessionHandle, state, details);

            if (completionCode)
            {
                return ipmi::response(completionCode);
            }
            activeSessionHandle = sessionHandle;
            maybeDetails = std::move(details);
        }
    }

    if (state == static_cast<uint8_t>(session::State::active) ||
        state == static_cast<uint8_t>(session::State::tearDownInProgress))
    {
        return ipmi::responseSuccess(activeSessionHandle, totalSessionCount,
                                     activeSessionCount, maybeDetails);
    }

    return ipmi::responseInvalidFieldRequest();
}

static std::unique_ptr<SysInfoParamStore> sysInfoParamStore;

static std::string sysInfoReadSystemName()
{
    // Use the BMC hostname as the "System Name."
    char hostname[HOST_NAME_MAX + 1] = {};
    if (gethostname(hostname, HOST_NAME_MAX) != 0)
    {
        perror("System info parameter: system name");
    }
    return hostname;
}

static constexpr uint8_t paramRevision = 0x11;
static constexpr size_t configParameterLength = 16;

static constexpr size_t smallChunkSize = 14;
static constexpr size_t fullChunkSize = 16;
static constexpr uint8_t progressMask = 0x3;
static constexpr uint8_t maxValidEncodingData = 0x02;

static constexpr uint8_t setComplete = 0x0;
static constexpr uint8_t setInProgress = 0x1;
static constexpr uint8_t commitWrite = 0x2;
static uint8_t transferStatus = setComplete;

static constexpr uint8_t configDataOverhead = 2;

// For EFI based system, 256 bytes is recommended.
static constexpr size_t maxBytesPerParameter = 256;

namespace ipmi
{
constexpr Cc ccParmNotSupported = 0x80;
constexpr Cc ccSetInProgressActive = 0x81;
constexpr Cc ccSystemInfoParameterSetReadOnly = 0x82;

static inline auto responseParmNotSupported()
{
    return response(ccParmNotSupported);
}
static inline auto responseSetInProgressActive()
{
    return response(ccSetInProgressActive);
}
static inline auto responseSystemInfoParameterSetReadOnly()
{
    return response(ccSystemInfoParameterSetReadOnly);
}
} // namespace ipmi

ipmi::RspType<uint8_t,                // Parameter revision
              std::optional<uint8_t>, // data1 / setSelector / ProgressStatus
              std::optional<std::vector<uint8_t>>> // data2-17
    ipmiAppGetSystemInfo(uint7_t reserved, bool getRevision,
                         uint8_t paramSelector, uint8_t setSelector,
                         uint8_t BlockSelector)
{
    if (reserved || (paramSelector >= invalidParamSelectorStart &&
                     paramSelector <= invalidParamSelectorEnd))
    {
        return ipmi::responseInvalidFieldRequest();
    }
    if (paramSelector >= oemCmdStart)
    {
        return ipmi::responseParmNotSupported();
    }
    if (getRevision)
    {
        return ipmi::responseSuccess(paramRevision, std::nullopt, std::nullopt);
    }

    if (paramSelector == 0)
    {
        return ipmi::responseSuccess(paramRevision, transferStatus,
                                     std::nullopt);
    }

    if (BlockSelector != 0) // 00h if parameter does not require a block number
    {
        return ipmi::responseParmNotSupported();
    }

    if (sysInfoParamStore == nullptr)
    {
        sysInfoParamStore = std::make_unique<SysInfoParamStore>();
        sysInfoParamStore->update(IPMI_SYSINFO_SYSTEM_NAME,
                                  sysInfoReadSystemName);
    }

    // Parameters other than Set In Progress are assumed to be strings.
    std::tuple<bool, std::string> ret =
        sysInfoParamStore->lookup(paramSelector);
    bool found = std::get<0>(ret);
    if (!found)
    {
        return ipmi::responseSensorInvalid();
    }
    std::string& paramString = std::get<1>(ret);
    std::vector<uint8_t> configData;
    size_t count = 0;
    if (setSelector == 0)
    {                               // First chunk has only 14 bytes.
        configData.emplace_back(0); // encoding
        configData.emplace_back(paramString.length()); // string length
        count = std::min(paramString.length(), smallChunkSize);
        configData.resize(count + configDataOverhead);
        std::copy_n(paramString.begin(), count,
                    configData.begin() + configDataOverhead); // 14 bytes chunk

        // Append zero's to remaining bytes
        if (configData.size() < configParameterLength)
        {
            std::fill_n(std::back_inserter(configData),
                        configParameterLength - configData.size(), 0x00);
        }
    }
    else
    {
        size_t offset = (setSelector * fullChunkSize) - configDataOverhead;
        if (offset >= paramString.length())
        {
            return ipmi::responseParmOutOfRange();
        }
        count = std::min(paramString.length() - offset, fullChunkSize);
        configData.resize(count);
        std::copy_n(paramString.begin() + offset, count,
                    configData.begin()); // 16 bytes chunk
    }
    return ipmi::responseSuccess(paramRevision, setSelector, configData);
}

ipmi::RspType<> ipmiAppSetSystemInfo(uint8_t paramSelector, uint8_t data1,
                                     std::vector<uint8_t> configData)
{
    if (paramSelector >= invalidParamSelectorStart &&
        paramSelector <= invalidParamSelectorEnd)
    {
        return ipmi::responseInvalidFieldRequest();
    }
    if (paramSelector >= oemCmdStart)
    {
        return ipmi::responseParmNotSupported();
    }

    if (paramSelector == 0)
    {
        // attempt to set the 'set in progress' value (in parameter #0)
        // when not in the set complete state.
        if ((transferStatus != setComplete) && (data1 == setInProgress))
        {
            return ipmi::responseSetInProgressActive();
        }
        // only following 2 states are supported
        if (data1 > setInProgress)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "illegal SetInProgress status");
            return ipmi::responseInvalidFieldRequest();
        }

        transferStatus = data1 & progressMask;
        return ipmi::responseSuccess();
    }

    if (configData.size() > configParameterLength)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    // Append zero's to remaining bytes
    if (configData.size() < configParameterLength)
    {
        fill_n(back_inserter(configData),
               (configParameterLength - configData.size()), 0x00);
    }

    if (!sysInfoParamStore)
    {
        sysInfoParamStore = std::make_unique<SysInfoParamStore>();
        sysInfoParamStore->update(IPMI_SYSINFO_SYSTEM_NAME,
                                  sysInfoReadSystemName);
    }

    // lookup
    std::tuple<bool, std::string> ret =
        sysInfoParamStore->lookup(paramSelector);
    bool found = std::get<0>(ret);
    std::string& paramString = std::get<1>(ret);
    if (!found)
    {
        // parameter does not exist. Init new
        paramString = "";
    }

    uint8_t setSelector = data1;
    size_t count = 0;
    if (setSelector == 0) // First chunk has only 14 bytes.
    {
        uint8_t encoding = configData.at(0);
        if (encoding > maxValidEncodingData)
        {
            return ipmi::responseInvalidFieldRequest();
        }

        size_t stringLen = configData.at(1); // string length
        // maxBytesPerParamter is 256. It will always be greater than stringLen
        // (unit8_t) if maxBytes changes in future, then following line is
        // needed.
        // stringLen = std::min(stringLen, maxBytesPerParameter);
        count = std::min(stringLen, smallChunkSize);
        count = std::min(count, configData.size());
        paramString.resize(stringLen); // reserve space
        std::copy_n(configData.begin() + configDataOverhead, count,
                    paramString.begin());
    }
    else
    {
        size_t offset = (setSelector * fullChunkSize) - configDataOverhead;
        if (offset >= paramString.length())
        {
            return ipmi::responseParmOutOfRange();
        }
        count = std::min(paramString.length() - offset, configData.size());
        std::copy_n(configData.begin(), count, paramString.begin() + offset);
    }
    sysInfoParamStore->update(paramSelector, paramString);
    return ipmi::responseSuccess();
}

#ifdef ENABLE_I2C_WHITELIST_CHECK
inline std::vector<uint8_t> convertStringToData(const std::string& command)
{
    std::istringstream iss(command);
    std::string token;
    std::vector<uint8_t> dataValue;
    while (std::getline(iss, token, ' '))
    {
        dataValue.emplace_back(
            static_cast<uint8_t>(std::stoul(token, nullptr, base_16)));
    }
    return dataValue;
}

static bool populateI2CControllerWRAllowlist()
{
    nlohmann::json data = nullptr;
    std::ifstream jsonFile(i2cControllerWRAllowlistFile);

    if (!jsonFile.good())
    {
        log<level::WARNING>(
            "i2c allow list file not found!",
            entry("FILE_NAME: %s", i2cControllerWRAllowlistFile));
        return false;
    }

    try
    {
        data = nlohmann::json::parse(jsonFile, nullptr, false);
    }
    catch (const nlohmann::json::parse_error& e)
    {
        log<level::ERR>("Corrupted i2c allow list config file",
                        entry("FILE_NAME: %s", i2cControllerWRAllowlistFile),
                        entry("MSG: %s", e.what()));
        return false;
    }

    try
    {
        // Example JSON Structure format
        // "filters": [
        //    {
        //      "Description": "Allow full read - ignore first byte write value
        //      for 0x40 to 0x4F",
        //      "busId": "0x01",
        //      "slaveAddr": "0x40",
        //      "slaveAddrMask": "0x0F",
        //      "command": "0x00",
        //      "commandMask": "0xFF"
        //    },
        //    {
        //      "Description": "Allow full read - first byte match 0x05 and
        //      ignore second byte",
        //      "busId": "0x01",
        //      "slaveAddr": "0x57",
        //      "slaveAddrMask": "0x00",
        //      "command": "0x05 0x00",
        //      "commandMask": "0x00 0xFF"
        //    },]

        nlohmann::json filters = data[filtersStr].get<nlohmann::json>();
        std::vector<i2cControllerWRAllowlist>& allowlist = getWRAllowlist();
        for (const auto& it : filters.items())
        {
            nlohmann::json filter = it.value();
            if (filter.is_null())
            {
                log<level::ERR>(
                    "Corrupted I2C controller write read allowlist config file",
                    entry("FILE_NAME: %s", i2cControllerWRAllowlistFile));
                return false;
            }
            const std::vector<uint8_t>& writeData =
                convertStringToData(filter[cmdStr].get<std::string>());
            const std::vector<uint8_t>& writeDataMask =
                convertStringToData(filter[cmdMaskStr].get<std::string>());
            if (writeDataMask.size() != writeData.size())
            {
                log<level::ERR>("I2C controller write read allowlist filter "
                                "mismatch for command & mask size");
                return false;
            }
            allowlist.push_back(
                {static_cast<uint8_t>(std::stoul(
                     filter[busIdStr].get<std::string>(), nullptr, base_16)),
                 static_cast<uint8_t>(
                     std::stoul(filter[targetAddrStr].get<std::string>(),
                                nullptr, base_16)),
                 static_cast<uint8_t>(
                     std::stoul(filter[targetAddrMaskStr].get<std::string>(),
                                nullptr, base_16)),
                 writeData, writeDataMask});
        }
        if (allowlist.size() != filters.size())
        {
            log<level::ERR>(
                "I2C controller write read allowlist filter size mismatch");
            return false;
        }
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(
            "I2C controller write read allowlist unexpected exception",
            entry("ERROR=%s", e.what()));
        return false;
    }
    return true;
}

static inline bool isWriteDataAllowlisted(const std::vector<uint8_t>& data,
                                          const std::vector<uint8_t>& dataMask,
                                          const std::vector<uint8_t>& writeData)
{
    std::vector<uint8_t> processedDataBuf(data.size());
    std::vector<uint8_t> processedReqBuf(dataMask.size());
    std::transform(writeData.begin(), writeData.end(), dataMask.begin(),
                   processedReqBuf.begin(), std::bit_or<uint8_t>());
    std::transform(data.begin(), data.end(), dataMask.begin(),
                   processedDataBuf.begin(), std::bit_or<uint8_t>());

    return (processedDataBuf == processedReqBuf);
}

static bool isCmdAllowlisted(uint8_t busId, uint8_t targetAddr,
                             std::vector<uint8_t>& writeData)
{
    std::vector<i2cControllerWRAllowlist>& allowList = getWRAllowlist();
    for (const auto& wlEntry : allowList)
    {
        if ((busId == wlEntry.busId) &&
            ((targetAddr | wlEntry.targetAddrMask) ==
             (wlEntry.targetAddr | wlEntry.targetAddrMask)))
        {
            const std::vector<uint8_t>& dataMask = wlEntry.dataMask;
            // Skip as no-match, if requested write data is more than the
            // write data mask size
            if (writeData.size() > dataMask.size())
            {
                continue;
            }
            if (isWriteDataAllowlisted(wlEntry.data, dataMask, writeData))
            {
                return true;
            }
        }
    }
    return false;
}
#else
static bool populateI2CControllerWRAllowlist()
{
    log<level::INFO>(
        "I2C_WHITELIST_CHECK is disabled, do not populate allowlist");
    return true;
}
#endif // ENABLE_I2C_WHITELIST_CHECK

/** @brief implements controller write read IPMI command which can be used for
 * low-level I2C/SMBus write, read or write-read access
 *  @param isPrivateBus -to indicate private bus usage
 *  @param busId - bus id
 *  @param channelNum - channel number
 *  @param reserved - skip 1 bit
 *  @param targetAddr - target address
 *  @param read count - number of bytes to be read
 *  @param writeData - data to be written
 *
 *  @returns IPMI completion code plus response data
 *   - readData - i2c response data
 */
ipmi::RspType<std::vector<uint8_t>>
    ipmiControllerWriteRead([[maybe_unused]] bool isPrivateBus, uint3_t busId,
                            [[maybe_unused]] uint4_t channelNum, bool reserved,
                            uint7_t targetAddr, uint8_t readCount,
                            std::vector<uint8_t> writeData)
{
    if (reserved)
    {
        return ipmi::responseInvalidFieldRequest();
    }
    const size_t writeCount = writeData.size();
    if (!readCount && !writeCount)
    {
        log<level::ERR>(
            "Controller write read command: Read & write count are 0");
        return ipmi::responseInvalidFieldRequest();
    }
#ifdef ENABLE_I2C_WHITELIST_CHECK
    if (!isCmdAllowlisted(static_cast<uint8_t>(busId),
                          static_cast<uint8_t>(targetAddr), writeData))
    {
        log<level::ERR>("Controller write read request blocked!",
                        entry("BUS=%d", static_cast<uint8_t>(busId)),
                        entry("ADDR=0x%x", static_cast<uint8_t>(targetAddr)));
        return ipmi::responseInvalidFieldRequest();
    }
#endif // ENABLE_I2C_WHITELIST_CHECK
    std::vector<uint8_t> readBuf(readCount);
    std::string i2cBus = "/dev/i2c-" +
                         std::to_string(static_cast<uint8_t>(busId));

    ipmi::Cc ret = ipmi::i2cWriteRead(i2cBus, static_cast<uint8_t>(targetAddr),
                                      writeData, readBuf);
    if (ret != ipmi::ccSuccess)
    {
        return ipmi::response(ret);
    }
    return ipmi::responseSuccess(readBuf);
}

void register_netfn_app_functions()
{
    // <Get Device ID>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdGetDeviceId, ipmi::Privilege::User,
                          ipmiAppGetDeviceId);

    // <Get BT Interface Capabilities>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdGetBtIfaceCapabilities,
                          ipmi::Privilege::User, ipmiAppGetBtCapabilities);

    // <Reset Watchdog Timer>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdResetWatchdogTimer,
                          ipmi::Privilege::Operator, ipmiAppResetWatchdogTimer);

    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdGetSessionInfo, ipmi::Privilege::User,
                          ipmiAppGetSessionInfo);

    // <Set Watchdog Timer>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdSetWatchdogTimer,
                          ipmi::Privilege::Operator, ipmiSetWatchdogTimer);

    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdCloseSession, ipmi::Privilege::Callback,
                          ipmiAppCloseSession);

    // <Get Watchdog Timer>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdGetWatchdogTimer, ipmi::Privilege::User,
                          ipmiGetWatchdogTimer);

    // <Get Self Test Results>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdGetSelfTestResults,
                          ipmi::Privilege::User, ipmiAppGetSelfTestResults);

    // <Get Device GUID>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdGetDeviceGuid, ipmi::Privilege::User,
                          ipmiAppGetDeviceGuid);

    // <Set ACPI Power State>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdSetAcpiPowerState,
                          ipmi::Privilege::Admin, ipmiSetAcpiPowerState);
    // <Get ACPI Power State>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdGetAcpiPowerState,
                          ipmi::Privilege::User, ipmiGetAcpiPowerState);

    // Note: For security reason, this command will be registered only when
    // there are proper I2C Controller write read allowlist
    if (populateI2CControllerWRAllowlist())
    {
        // Note: For security reasons, registering controller write read as
        // admin privilege command, even though IPMI 2.0 specification allows it
        // as operator privilege.
        ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                              ipmi::app::cmdMasterWriteRead,
                              ipmi::Privilege::Admin, ipmiControllerWriteRead);
    }

    // <Get System GUID Command>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdGetSystemGuid, ipmi::Privilege::User,
                          ipmiAppGetSystemGuid);

    // <Get Channel Cipher Suites Command>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdGetChannelCipherSuites,
                          ipmi::Privilege::None, getChannelCipherSuites);

    // <Get System Info Command>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdGetSystemInfoParameters,
                          ipmi::Privilege::User, ipmiAppGetSystemInfo);
    // <Set System Info Command>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdSetSystemInfoParameters,
                          ipmi::Privilege::Admin, ipmiAppSetSystemInfo);
    return;
}
