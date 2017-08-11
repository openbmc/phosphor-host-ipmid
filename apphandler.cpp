#include "apphandler.h"

#include "app/channel.hpp"
#include "app/watchdog.hpp"
#include "ipmid.hpp"
#include "nlohmann/json.hpp"
#include "sys_info_param.hpp"
#include "transporthandler.hpp"
#include "types.hpp"
#include "utils.hpp"

#include <arpa/inet.h>
#include <limits.h>
#include <mapper.h>
#include <stdint.h>
#include <stdio.h>
#include <systemd/sd-bus.h>
#include <unistd.h>

#include "host-ipmid/ipmid-api.h"

#if __has_include(<filesystem>)
#include <filesystem>
#elif __has_include(<experimental/filesystem>)
#include <experimental/filesystem>
namespace std
{
// splice experimental::filesystem into std
namespace filesystem = std::experimental::filesystem;
} // namespace std
#else
#error filesystem not available
#endif

#include <algorithm>
#include <array>
#include <cstddef>
#include <fstream>
#include <memory>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <string>
#include <tuple>
#include <vector>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/Software/Activation/server.hpp>
#include <xyz/openbmc_project/Software/Version/server.hpp>

extern sd_bus* bus;

constexpr auto bmc_interface = "xyz.openbmc_project.Inventory.Item.Bmc";
constexpr auto bmc_guid_interface = "xyz.openbmc_project.Common.UUID";
constexpr auto bmc_guid_property = "UUID";
constexpr auto bmc_guid_len = 16;

static constexpr auto redundancyIntf =
    "xyz.openbmc_project.Software.RedundancyPriority";
static constexpr auto versionIntf = "xyz.openbmc_project.Software.Version";
static constexpr auto activationIntf =
    "xyz.openbmc_project.Software.Activation";
static constexpr auto softwareRoot = "/xyz/openbmc_project/software";

void register_netfn_app_functions() __attribute__((constructor));

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using Version = sdbusplus::xyz::openbmc_project::Software::server::Version;
using Activation =
    sdbusplus::xyz::openbmc_project::Software::server::Activation;
namespace fs = std::filesystem;

// Offset in get device id command.
typedef struct
{
    uint8_t id;
    uint8_t revision;
    uint8_t fw[2];
    uint8_t ipmi_ver;
    uint8_t addn_dev_support;
    uint8_t manuf_id[3];
    uint8_t prod_id[2];
    uint8_t aux[4];
} __attribute__((packed)) ipmi_device_id_t;

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
std::string getActiveSoftwareVersionInfo()
{
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};

    std::string revision{};
    auto objectTree =
        ipmi::getAllDbusObjects(bus, softwareRoot, redundancyIntf, "");
    if (objectTree.empty())
    {
        log<level::ERR>("No Obj has implemented the s/w redundancy interface",
                        entry("INTERFACE=%s", redundancyIntf));
        elog<InternalFailure>();
    }

    auto objectFound = false;
    for (auto& softObject : objectTree)
    {
        auto service = ipmi::getService(bus, redundancyIntf, softObject.first);
        auto objValueTree = ipmi::getManagedObjects(bus, service, softwareRoot);

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
                    redundancyPriorityProps.at("Priority").get<uint8_t>();
                auto purpose = versionProps.at("Purpose").get<std::string>();
                auto activation =
                    activationProps.at("Activation").get<std::string>();
                auto version = versionProps.at("Version").get<std::string>();
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

ipmi_ret_t ipmi_app_set_acpi_power_state(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                         ipmi_request_t request,
                                         ipmi_response_t response,
                                         ipmi_data_len_t data_len,
                                         ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;

    log<level::DEBUG>("IPMI SET ACPI STATE Ignoring for now\n");
    return rc;
}

typedef struct
{
    char major;
    char minor;
    uint16_t d[2];
} rev_t;

/* Currently supports the vx.x-x-[-x] and v1.x.x-x-[-x] format. It will     */
/* return -1 if not in those formats, this routine knows how to parse       */
/* version = v0.6-19-gf363f61-dirty                                         */
/*            ^ ^ ^^          ^                                             */
/*            | |  |----------|-- additional details                        */
/*            | |---------------- Minor                                     */
/*            |------------------ Major                                     */
/* and version = v1.99.10-113-g65edf7d-r3-0-g9e4f715                        */
/*                ^ ^  ^^ ^                                                 */
/*                | |  |--|---------- additional details                    */
/*                | |---------------- Minor                                 */
/*                |------------------ Major                                 */
/* Additional details : If the option group exists it will force Auxiliary  */
/* Firmware Revision Information 4th byte to 1 indicating the build was     */
/* derived with additional edits                                            */
int convert_version(const char* p, rev_t* rev)
{
    std::string s(p);
    std::string token;
    uint16_t commits;

    auto location = s.find_first_of('v');
    if (location != std::string::npos)
    {
        s = s.substr(location + 1);
    }

    if (!s.empty())
    {
        location = s.find_first_of(".");
        if (location != std::string::npos)
        {
            rev->major =
                static_cast<char>(std::stoi(s.substr(0, location), 0, 16));
            token = s.substr(location + 1);
        }

        if (!token.empty())
        {
            location = token.find_first_of(".-");
            if (location != std::string::npos)
            {
                rev->minor = static_cast<char>(
                    std::stoi(token.substr(0, location), 0, 16));
                token = token.substr(location + 1);
            }
        }

        // Capture the number of commits on top of the minor tag.
        // I'm using BE format like the ipmi spec asked for
        location = token.find_first_of(".-");
        if (!token.empty())
        {
            commits = std::stoi(token.substr(0, location), 0, 16);
            rev->d[0] = (commits >> 8) | (commits << 8);

            // commit number we skip
            location = token.find_first_of(".-");
            if (location != std::string::npos)
            {
                token = token.substr(location + 1);
            }
        }
        else
        {
            rev->d[0] = 0;
        }

        if (location != std::string::npos)
        {
            token = token.substr(location + 1);
        }

        // Any value of the optional parameter forces it to 1
        location = token.find_first_of(".-");
        if (location != std::string::npos)
        {
            token = token.substr(location + 1);
        }
        commits = (!token.empty()) ? 1 : 0;

        // We do this operation to get this displayed in least significant bytes
        // of ipmitool device id command.
        rev->d[1] = (commits >> 8) | (commits << 8);
    }

    return 0;
}

ipmi_ret_t ipmi_app_get_device_id(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                  ipmi_request_t request,
                                  ipmi_response_t response,
                                  ipmi_data_len_t data_len,
                                  ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    int r = -1;
    rev_t rev = {0};
    static ipmi_device_id_t dev_id{};
    static bool dev_id_initialized = false;
    const char* filename = "/usr/share/ipmi-providers/dev_id.json";

    // Data length
    *data_len = sizeof(dev_id);

    if (!dev_id_initialized)
    {
        try
        {
            auto version = getActiveSoftwareVersionInfo();
            r = convert_version(version.c_str(), &rev);
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
            // our SDR is normal working condition, so mask:
            dev_id.fw[0] = 0x7F & rev.major;

            rev.minor = (rev.minor > 99 ? 99 : rev.minor);
            dev_id.fw[1] = rev.minor % 10 + (rev.minor / 10) * 16;
            memcpy(&dev_id.aux, rev.d, 4);
        }

        // IPMI Spec version 2.0
        dev_id.ipmi_ver = 2;

        std::ifstream dev_id_file(filename);
        if (dev_id_file.is_open())
        {
            auto data = nlohmann::json::parse(dev_id_file, nullptr, false);
            if (!data.is_discarded())
            {
                dev_id.id = data.value("id", 0);
                dev_id.revision = data.value("revision", 0);
                dev_id.addn_dev_support = data.value("addn_dev_support", 0);
                dev_id.manuf_id[2] = data.value("manuf_id", 0) >> 16;
                dev_id.manuf_id[1] = data.value("manuf_id", 0) >> 8;
                dev_id.manuf_id[0] = data.value("manuf_id", 0);
                dev_id.prod_id[1] = data.value("prod_id", 0) >> 8;
                dev_id.prod_id[0] = data.value("prod_id", 0);
                dev_id.aux[3] = data.value("aux", 0);
                dev_id.aux[2] = data.value("aux", 0) >> 8;
                dev_id.aux[1] = data.value("aux", 0) >> 16;
                dev_id.aux[0] = data.value("aux", 0) >> 24;

                // Don't read the file every time if successful
                dev_id_initialized = true;
            }
            else
            {
                log<level::ERR>("Device ID JSON parser failure");
                rc = IPMI_CC_UNSPECIFIED_ERROR;
            }
        }
        else
        {
            log<level::ERR>("Device ID file not found");
            rc = IPMI_CC_UNSPECIFIED_ERROR;
        }
    }

    // Pack the actual response
    memcpy(response, &dev_id, *data_len);

    return rc;
}

ipmi_ret_t ipmi_app_get_self_test_results(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                          ipmi_request_t request,
                                          ipmi_response_t response,
                                          ipmi_data_len_t data_len,
                                          ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;

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

    char selftestresults[2] = {0};

    *data_len = 2;

    selftestresults[0] = 0x56;
    selftestresults[1] = 0;

    memcpy(response, selftestresults, *data_len);

    return rc;
}

ipmi_ret_t ipmi_app_get_device_guid(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                    ipmi_request_t request,
                                    ipmi_response_t response,
                                    ipmi_data_len_t data_len,
                                    ipmi_context_t context)
{
    const char* objname = "/org/openbmc/control/chassis0";
    const char* iface = "org.freedesktop.DBus.Properties";
    const char* chassis_iface = "org.openbmc.control.Chassis";
    sd_bus_message* reply = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int r = 0;
    char* uuid = NULL;
    char* busname = NULL;

    // UUID is in RFC4122 format. Ex: 61a39523-78f2-11e5-9862-e6402cfc3223
    // Per IPMI Spec 2.0 need to convert to 16 hex bytes and reverse the byte
    // order
    // Ex: 0x2332fc2c40e66298e511f2782395a361

    const int resp_size = 16;     // Response is 16 hex bytes per IPMI Spec
    uint8_t resp_uuid[resp_size]; // Array to hold the formatted response
    // Point resp end of array to save in reverse order
    int resp_loc = resp_size - 1;
    int i = 0;
    char* tokptr = NULL;
    char* id_octet = NULL;

    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;

    // Call Get properties method with the interface and property name
    r = mapper_get_service(bus, objname, &busname);
    if (r < 0)
    {
        log<level::ERR>("Failed to get bus name", entry("BUS=%s", objname),
                        entry("ERRNO=0x%X", -r));
        goto finish;
    }
    r = sd_bus_call_method(bus, busname, objname, iface, "Get", &error, &reply,
                           "ss", chassis_iface, "uuid");
    if (r < 0)
    {
        log<level::ERR>("Failed to call Get Method", entry("ERRNO=0x%X", -r));
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        goto finish;
    }

    r = sd_bus_message_read(reply, "v", "s", &uuid);
    if (r < 0 || uuid == NULL)
    {
        log<level::ERR>("Failed to get a response", entry("ERRNO=0x%X", -r));
        rc = IPMI_CC_RESPONSE_ERROR;
        goto finish;
    }

    // Traverse the UUID
    // Get the UUID octects separated by dash
    id_octet = strtok_r(uuid, "-", &tokptr);

    if (id_octet == NULL)
    {
        // Error
        log<level::ERR>("Unexpected UUID format", entry("UUID=%s", uuid));
        rc = IPMI_CC_RESPONSE_ERROR;
        goto finish;
    }

    while (id_octet != NULL)
    {
        // Calculate the octet string size since it varies
        // Divide it by 2 for the array size since 1 byte is built from 2 chars
        int tmp_size = strlen(id_octet) / 2;

        for (i = 0; i < tmp_size; i++)
        {
            // Holder of the 2 chars that will become a byte
            char tmp_array[3] = {0};
            strncpy(tmp_array, id_octet, 2); // 2 chars at a time

            int resp_byte = strtoul(tmp_array, NULL, 16); // Convert to hex byte
            // Copy end to first
            memcpy((void*)&resp_uuid[resp_loc], &resp_byte, 1);
            resp_loc--;
            id_octet += 2; // Finished with the 2 chars, advance
        }
        id_octet = strtok_r(NULL, "-", &tokptr); // Get next octet
    }

    // Data length
    *data_len = resp_size;

    // Pack the actual response
    memcpy(response, &resp_uuid, *data_len);

finish:
    sd_bus_error_free(&error);
    reply = sd_bus_message_unref(reply);
    free(busname);

    return rc;
}

ipmi_ret_t ipmi_app_get_bt_capabilities(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                        ipmi_request_t request,
                                        ipmi_response_t response,
                                        ipmi_data_len_t data_len,
                                        ipmi_context_t context)
{

    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;

    // Per IPMI 2.0 spec, the input and output buffer size must be the max
    // buffer size minus one byte to allocate space for the length byte.
    uint8_t str[] = {0x01, MAX_IPMI_BUFFER - 1, MAX_IPMI_BUFFER - 1, 0x0A,
                     0x01};

    // Data length
    *data_len = sizeof(str);

    // Pack the actual response
    memcpy(response, &str, *data_len);

    return rc;
}

ipmi_ret_t ipmi_app_wildcard_handler(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                     ipmi_request_t request,
                                     ipmi_response_t response,
                                     ipmi_data_len_t data_len,
                                     ipmi_context_t context)
{
    // Status code.
    ipmi_ret_t rc = IPMI_CC_INVALID;

    *data_len = strlen("THIS IS WILDCARD");

    // Now pack actual response
    memcpy(response, "THIS IS WILDCARD", *data_len);

    return rc;
}

ipmi_ret_t ipmi_app_get_sys_guid(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                 ipmi_request_t request,
                                 ipmi_response_t response,
                                 ipmi_data_len_t data_len,
                                 ipmi_context_t context)

{
    ipmi_ret_t rc = IPMI_CC_OK;
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};

    try
    {
        // Get the Inventory object implementing BMC interface
        ipmi::DbusObjectInfo bmcObject =
            ipmi::getDbusObject(bus, bmc_interface);

        // Read UUID property value from bmcObject
        // UUID is in RFC4122 format Ex: 61a39523-78f2-11e5-9862-e6402cfc3223
        auto variant =
            ipmi::getDbusProperty(bus, bmcObject.second, bmcObject.first,
                                  bmc_guid_interface, bmc_guid_property);
        std::string guidProp = variant.get<std::string>();

        // Erase "-" characters from the property value
        guidProp.erase(std::remove(guidProp.begin(), guidProp.end(), '-'),
                       guidProp.end());

        auto guidPropLen = guidProp.length();
        // Validate UUID data
        // Divide by 2 as 1 byte is built from 2 chars
        if ((guidPropLen <= 0) || ((guidPropLen / 2) != bmc_guid_len))

        {
            log<level::ERR>("Invalid UUID property value",
                            entry("UUID_LENGTH=%d", guidPropLen));
            return IPMI_CC_RESPONSE_ERROR;
        }

        // Convert data in RFC4122(MSB) format to LSB format
        // Get 2 characters at a time as 1 byte is built from 2 chars and
        // convert to hex byte
        // TODO: Data printed for GUID command is not as per the
        // GUID format defined in IPMI specification 2.0 section 20.8
        // Ticket raised: https://sourceforge.net/p/ipmitool/bugs/501/
        uint8_t respGuid[bmc_guid_len];
        for (size_t i = 0, respLoc = (bmc_guid_len - 1);
             i < guidPropLen && respLoc >= 0; i += 2, respLoc--)
        {
            auto value = static_cast<uint8_t>(
                std::stoi(guidProp.substr(i, 2).c_str(), NULL, 16));
            respGuid[respLoc] = value;
        }

        *data_len = bmc_guid_len;
        memcpy(response, &respGuid, bmc_guid_len);
    }
    catch (const InternalFailure& e)
    {
        log<level::ERR>("Failed in reading BMC UUID property",
                        entry("INTERFACE=%s", bmc_interface),
                        entry("PROPERTY_INTERFACE=%s", bmc_guid_interface),
                        entry("PROPERTY=%s", bmc_guid_property));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    return rc;
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

ipmi_ret_t ipmi_app_set_system_info(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                    ipmi_request_t request,
                                    ipmi_response_t response,
                                    ipmi_data_len_t dataLen,
                                    ipmi_context_t context)
{
    printf("Handling IPMI_CMD_SET_SYSTEM_INFO Netfn:[0x%X], Cmd:[0x%X]\n",
           netfn, cmd);
    printf("Setting parameters is not implemented.\n");
    return IPMI_CC_INVALID;
}

typedef struct
{
    uint8_t paramRevision;
    uint8_t setSelector;
    union
    {
        struct
        {
            uint8_t encoding;
            uint8_t stringLen;
            uint8_t stringData0[14];
        } __attribute__((packed));
        uint8_t stringDataN[16];
        uint8_t byteData;
    };
} __attribute__((packed)) ipmi_sys_info_resp_t;

// Split a string into (up to) 16-byte chunks as expected in response for get
// system info parameter.
// Args:
//   fullString: Input string to be split
//   chunkIndex: Index of the chunk to be written out
//   chunk: Output data buffer; must have 14 byte capacity if chunk_index = 0
//          and 16-byte capacity otherwise
// Returns the number of bytes written into the output buffer, or -EINVAL for
// invalid arguments.
static int splitStringParam(const std::string& fullString, int chunkIndex,
                            uint8_t* chunk)
{
    constexpr int maxChunk = 255;
    if (chunkIndex > maxChunk || chunk == nullptr)
    {
        return -EINVAL;
    }
    const size_t fullLength = fullString.length();
    // Index to the beginning of the chunk data in full_string, after clamping
    // to its length.
    const size_t chunkStart = std::min(
        fullLength, static_cast<size_t>(std::max(0, chunkIndex * 16 - 2)));
    const size_t chunkLength = chunkIndex == 0 ? 14 : 16;
    const size_t chunkEnd = std::min(fullLength, chunkStart + chunkLength);

    // Does nothing if chunk_start = chunk_end.
    std::copy(&fullString[chunkStart], &fullString[chunkEnd], chunk);
    const size_t bytesWritten = chunkEnd - chunkStart;
    std::fill(&chunk[bytesWritten], &chunk[16], 0);
    return bytesWritten;
}

static int packGetSysInfoResp(const std::string& param_string,
                              uint8_t set_selector, ipmi_sys_info_resp_t* resp)
{
    uint8_t* data_buffer = resp->stringDataN;
    resp->setSelector = set_selector;
    if (resp->setSelector == 0) // First chunk has only 14 bytes.
    {
        resp->encoding = 0;
        resp->stringLen = param_string.length();
        data_buffer = resp->stringData0;
    }
    return splitStringParam(param_string, resp->setSelector, data_buffer);
}

ipmi_ret_t ipmi_app_get_system_info(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                    ipmi_request_t request,
                                    ipmi_response_t response,
                                    ipmi_data_len_t dataLen,
                                    ipmi_context_t context)
{
    ipmi_sys_info_resp_t resp = {};
    size_t respLen = 0;
    uint8_t* const reqData = static_cast<uint8_t*>(request);
    printf("Handling IPMI_CMD_GET_SYSTEM_INFO Netfn:[0x%X], Cmd:[0x%X]\n",
           netfn, cmd);
    const uint8_t paramRequested = reqData[1];
    std::string paramString;
    bool found;
    std::tuple<bool, std::string> ret;

    if (*dataLen < 4)
    {
        fprintf(stderr, "command is too short (length %zu)\n", *dataLen);
        return IPMI_CC_INVALID;
    }

    // Parameters revision as of IPMI spec v2.0 rev. 1.1 (Feb 11, 2014 E6)
    resp.paramRevision = 0x11;
    if (reqData[0] & 0x80) // Get parameter revision only
    {
        respLen = 1;
        goto writeResponse;
    }

    printf("Get System Info Parameter %x, set %u\n", paramRequested,
           resp.setSelector);

    // The "Set In Progress" parameter can be used for rollback of parameter
    // data and is not implemented.
    if (paramRequested == 0)
    {
        resp.byteData = 0;
        respLen = 2;
        goto writeResponse;
    }

    if (sysInfoParamStore == nullptr)
    {
        sysInfoParamStore = std::make_unique<SysInfoParamStore>();
        sysInfoParamStore->update(IPMI_SYSINFO_SYSTEM_NAME,
                                  sysInfoReadSystemName);
    }

    // Parameters other than Set In Progress are assumed to be strings.
    ret = sysInfoParamStore->lookup(paramRequested);
    found = std::get<0>(ret);
    paramString = std::get<1>(ret);
    if (!found)
    {
        return IPMI_CC_SYSTEM_INFO_PARAMETER_NOT_SUPPORTED;
    }
    // TODO: Cache each parameter across multiple calls, until the whole string
    // has been read out. Otherwise, it's possible for a parameter to change
    // between requests for its chunks, returning chunks incoherent with each
    // other. For now, the parameter store is simply required to have only
    // idempotent callbacks.
    packGetSysInfoResp(paramString, reqData[2], &resp);
    respLen = sizeof(resp); // Write entire string data chunk in response.

writeResponse:
    memcpy(response, &resp, sizeof(resp));
    *dataLen = respLen;
    return IPMI_CC_OK;
}

void register_netfn_app_functions()
{
    // <Get BT Interface Capabilities>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_CAP_BIT, NULL,
                           ipmi_app_get_bt_capabilities, PRIVILEGE_USER);

    // <Wildcard Command>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_WILDCARD, NULL,
                           ipmi_app_wildcard_handler, PRIVILEGE_USER);

    // <Reset Watchdog Timer>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_RESET_WD, NULL,
                           ipmi_app_watchdog_reset, PRIVILEGE_OPERATOR);

    // <Set Watchdog Timer>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_SET_WD, NULL,
                           ipmi_app_watchdog_set, PRIVILEGE_OPERATOR);

    // <Get Watchdog Timer>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_WD, NULL,
                           ipmi_app_watchdog_get, PRIVILEGE_OPERATOR);

    // <Get Device ID>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_DEVICE_ID, NULL,
                           ipmi_app_get_device_id, PRIVILEGE_USER);

    // <Get Self Test Results>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_SELF_TEST_RESULTS, NULL,
                           ipmi_app_get_self_test_results, PRIVILEGE_USER);

    // <Get Device GUID>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_DEVICE_GUID, NULL,
                           ipmi_app_get_device_guid, PRIVILEGE_USER);

    // <Set ACPI Power State>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_SET_ACPI, NULL,
                           ipmi_app_set_acpi_power_state, PRIVILEGE_ADMIN);

    // <Get Channel Access>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_CHANNEL_ACCESS, NULL,
                           ipmi_get_channel_access, PRIVILEGE_USER);

    // <Get Channel Info Command>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_CHAN_INFO, NULL,
                           ipmi_app_channel_info, PRIVILEGE_USER);

    // <Get System GUID Command>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_SYS_GUID, NULL,
                           ipmi_app_get_sys_guid, PRIVILEGE_USER);

    // <Get Channel Cipher Suites Command>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_CHAN_CIPHER_SUITES, NULL,
                           getChannelCipherSuites, PRIVILEGE_CALLBACK);

    // <Set System Info Command>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_SET_SYSTEM_INFO, NULL,
                           ipmi_app_set_system_info, PRIVILEGE_ADMIN);

    // <Get System Info Command>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_SYSTEM_INFO, NULL,
                           ipmi_app_get_system_info, PRIVILEGE_USER);
    return;
}
