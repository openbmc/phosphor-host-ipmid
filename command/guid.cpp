#include "guid.hpp"

#include <ipmid/api.h>
#include <mapper.h>

#include <ipmid/utils.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <sstream>
#include <string>

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

static std::optional<command::Guid> guid;

namespace command
{

std::unique_ptr<sdbusplus::bus::match_t> matchPtr(nullptr);

static constexpr auto propInterface = "xyz.openbmc_project.Common.UUID";
static constexpr auto uuidProperty = "UUID";
static constexpr auto subtreePath = "/xyz/openbmc_project/inventory";

static void rfcToGuid(std::string rfc4122, Guid& uuid)
{
    using Argument = xyz::openbmc_project::Common::InvalidArgument;
    // UUID is in RFC4122 format. Ex: 61a39523-78f2-11e5-9862-e6402cfc3223
    // Per IPMI Spec 2.0 need to convert to 16 hex bytes and reverse the byte
    // order
    // Ex: 0x2332fc2c40e66298e511f2782395a361
    constexpr size_t uuidHexLength = (2 * BMC_GUID_LEN);
    constexpr size_t uuidRfc4122Length = (uuidHexLength + 4);

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
        long b;
        try
        {
            b = std::stoul(rfc4122.substr(ind, 2), nullptr, 16);
        }
        catch (const std::exception& e)
        {
            elog<InvalidArgument>(Argument::ARGUMENT_NAME("rfc4122"),
                                  Argument::ARGUMENT_VALUE(rfc4122.c_str()));
        }

        uuid[BMC_GUID_LEN - (ind / 2) - 1] = static_cast<uint8_t>(b);
    }
    return;
}

// Canned System GUID for when the Chassis DBUS object is not populated
static constexpr Guid fakeGuid = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                  0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                                  0x0D, 0x0E, 0x0F, 0x10};
const Guid& getSystemGUID()
{
    if (guid.has_value())
    {
        return guid.value();
    }

    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};

    ipmi::Value propValue;
    try
    {
        const auto& [objPath, service] = ipmi::getDbusObject(bus, propInterface,
                                                             subtreePath);
        // Read UUID property value from bmcObject
        // UUID is in RFC4122 format Ex: 61a39523-78f2-11e5-9862-e6402cfc3223
        propValue = ipmi::getDbusProperty(bus, service, objPath, propInterface,
                                          uuidProperty);
    }
    catch (const sdbusplus::exception_t& e)
    {
        lg2::error("Failed in reading BMC UUID property: {ERROR}", "ERROR", e);
        return fakeGuid;
    }

    std::string rfc4122Uuid = std::get<std::string>(propValue);
    try
    {
        // convert to IPMI format
        Guid tmpGuid{};
        rfcToGuid(rfc4122Uuid, tmpGuid);
        guid = tmpGuid;
    }
    catch (const InvalidArgument& e)
    {
        lg2::error("Failed in parsing BMC UUID property: {VALUE}", "VALUE",
                   rfc4122Uuid.c_str());
        return fakeGuid;
    }
    return guid.value();
}

void registerGUIDChangeCallback()
{
    if (matchPtr == nullptr)
    {
        using namespace sdbusplus::bus::match::rules;
        sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};

        try
        {
            matchPtr = std::make_unique<sdbusplus::bus::match_t>(
                bus, propertiesChangedNamespace(subtreePath, propInterface),
                [](sdbusplus::message_t& m) {
                try
                {
                    std::string iface{};
                    std::map<std::string, ipmi::Value> pdict{};
                    m.read(iface, pdict);
                    if (iface != propInterface)
                    {
                        return;
                    }
                    auto guidStr = std::get<std::string>(pdict.at("UUID"));
                    Guid tmpGuid{};
                    rfcToGuid(guidStr, tmpGuid);
                    guid = tmpGuid;
                }
                catch (const std::exception& e)
                {
                    // signal contained invalid guid; ignore it
                    lg2::error(
                        "Failed to parse propertiesChanged signal: {ERROR}",
                        "ERROR", e);
                }
            });
        }
        catch (const std::exception& e)
        {
            lg2::error("Failed to create dbus match: {ERROR}", "ERROR", e);
        }
    }
}

} // namespace command
