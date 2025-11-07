#include "config.h"

#include <ipmid/api.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <nlohmann/json.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/message/types.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
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

static constexpr auto redundancyIntf =
    "xyz.openbmc_project.Software.RedundancyPriority";
static constexpr auto versionIntf = "xyz.openbmc_project.Software.Version";
static constexpr auto activationIntf =
    "xyz.openbmc_project.Software.Activation";
static constexpr auto softwareRoot = "/xyz/openbmc_project/software";

void registerNetFnAppFunctions() __attribute__((constructor));

using namespace phosphor::logging;
using namespace sdbusplus::error::xyz::openbmc_project::common;
using Version = sdbusplus::server::xyz::openbmc_project::software::Version;
using Activation =
    sdbusplus::server::xyz::openbmc_project::software::Activation;
using BMCState = sdbusplus::server::xyz::openbmc_project::state::BMC;
namespace fs = std::filesystem;

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
        objectTree =
            ipmi::getAllDbusObjects(*ctx->bus, softwareRoot, redundancyIntf);
    }
    catch (const sdbusplus::exception_t& e)
    {
        lg2::error("Failed to fetch redundancy object from dbus, "
                   "interface: {INTERFACE},  error: {ERROR}",
                   "INTERFACE", redundancyIntf, "ERROR", e);
        elog<InternalFailure>();
    }

    auto objectFound = false;
    for (auto& softObject : objectTree)
    {
        auto service =
            ipmi::getService(*ctx->bus, redundancyIntf, softObject.first);
        auto objValueTree =
            ipmi::getManagedObjects(*ctx->bus, service, softwareRoot);

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
                lg2::error("error message: {ERROR}", "ERROR", e);
            }
        }
    }

    if (!objectFound)
    {
        lg2::error("Could not found an BMC software Object");
        elog<InternalFailure>();
    }

    return revision;
}

bool getCurrentBmcStateWithFallback(ipmi::Context::ptr& ctx,
                                    const bool fallbackAvailability)
{
    // Get the Inventory object implementing the BMC interface
    ipmi::DbusObjectInfo bmcObject{};
    boost::system::error_code ec =
        ipmi::getDbusObject(ctx, BMCState::interface, bmcObject);
    std::string bmcState{};
    if (ec.value())
    {
        return fallbackAvailability;
    }
    ec = ipmi::getDbusProperty(
        ctx, bmcObject.second, bmcObject.first, BMCState::interface,
        BMCState::property_names::current_bmc_state, bmcState);
    if (!ec.value())
    {
        return fallbackAvailability;
    }
    return BMCState::convertBMCStateFromString(bmcState) ==
           BMCState::BMCState::Ready;
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
            std::string str = m[matches[0]].str();
            const auto& [ptr, ec] =
                std::from_chars(str.data(), str.data() + str.size(), val);
            if (ec != std::errc() || ptr != str.data() + str.size())
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
            std::string str = m[matches[1]].str();
            const auto& [ptr, ec] =
                std::from_chars(str.data(), str.data() + str.size(), val);
            if (ec != std::errc() || ptr != str.data() + str.size())
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

                std::string str = m[matches[i + 2]].str();
                const char* cstr = str.c_str();
                auto [ptr,
                      ec] = std::from_chars(cstr, cstr + str.size(), val, 16);
                if (ec != std::errc() || ptr != cstr + str.size())
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

    static bool haveBMCVersion = false;
    if (!haveBMCVersion || !dev_id_initialized)
    {
        int r = -1;
        Revision rev = {0, 0, {0, 0, 0, 0}};
        try
        {
            auto version = getActiveSoftwareVersionInfo(ctx);
            r = convertVersion(version, rev);
        }
        catch (const std::exception& e)
        {
            lg2::error("error message: {ERROR}", "ERROR", e);
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
                if (!(AUX_0_MATCH_INDEX || AUX_1_MATCH_INDEX ||
                      AUX_2_MATCH_INDEX || AUX_3_MATCH_INDEX))
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
                lg2::error("Device ID JSON parser failure");
                return ipmi::responseUnspecifiedError();
            }
        }
        else
        {
            lg2::error("Device ID file not found");
            return ipmi::responseUnspecifiedError();
        }
    }

    // Set availability to the actual current BMC state
    devId.fw[0] &= ipmiDevIdFw1Mask;
    if (!getCurrentBmcStateWithFallback(ctx, defaultActivationSetting))
    {
        devId.fw[0] |= (1 << ipmiDevIdStateShift);
    }

    return ipmi::responseSuccess(
        devId.id, devId.revision, devId.fw[0], devId.fw[1], devId.ipmiVer,
        devId.addnDevSupport, devId.manufId, devId.prodId, devId.aux);
}

void registerNetFnAppFunctions()
{
    // OEM libraries should use ipmi::prioOemBase to override default
    // implementation of IPMI commands that use ipmi::prioOpenBmcBase

    // <Get Device ID>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnApp,
                          ipmi::app::cmdGetDeviceId, ipmi::Privilege::User,
                          ipmiAppGetDeviceId);
}
