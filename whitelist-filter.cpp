#include <algorithm>
#include <array>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <ipmiwhitelist.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <settings.hpp>
#include <xyz/openbmc_project/Control/Security/RestrictionMode/server.hpp>

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

namespace ipmi
{

// put the filter provider in an unnamed namespace
namespace
{

/** @class WhitelistFilter
 *
 * Class that implements an IPMI message filter based
 * on incoming interface and a restriction mode setting
 */
class WhitelistFilter
{
  public:
    WhitelistFilter();
    ~WhitelistFilter() = default;
    WhitelistFilter(WhitelistFilter const&) = delete;
    WhitelistFilter(WhitelistFilter&&) = delete;
    WhitelistFilter& operator=(WhitelistFilter const&) = delete;
    WhitelistFilter& operator=(WhitelistFilter&&) = delete;

  private:
    void postInit();
    void cacheRestrictedMode(const std::vector<std::string>& devices);
    void handleRestrictedModeChange(
        sdbusplus::message_t& m,
        const std::map<std::string, size_t>& deviceList);
    ipmi::Cc filterMessage(ipmi::message::Request::ptr request);

    std::vector<bool> restrictedMode;
    std::shared_ptr<sdbusplus::asio::connection> bus;
    std::unique_ptr<settings::Objects> objects;
    std::unique_ptr<sdbusplus::bus::match_t> modeChangeMatch;

    static constexpr const char restrictionModeIntf[] =
        "xyz.openbmc_project.Control.Security.RestrictionMode";
};

WhitelistFilter::WhitelistFilter()
{
    bus = getSdBus();

    log<level::INFO>("Loading whitelist filter");
    ipmi::registerFilter(ipmi::prioOpenBmcBase,
                         [this](ipmi::message::Request::ptr request) {
                             return filterMessage(request);
                         });

    // wait until io->run is going to fetch RestrictionMode
    post_work([this]() { postInit(); });
}

/** @brief Get RestrictionMode of the devices which has RestrictionMode support
 * enabled
 *  @param[in] devices - vector of devices object path
 *  @returns void.
 */

void WhitelistFilter::cacheRestrictedMode(
    const std::vector<std::string>& devices)
{
    using namespace sdbusplus::xyz::openbmc_project::Control::Security::server;
    std::string restrictionModeSetting;
    std::string restrictionModeService;

    for (auto& dev : devices)
    {
        try
        {
            restrictionModeSetting = dev;
            restrictionModeService =
                objects->service(restrictionModeSetting, restrictionModeIntf);
        }
        catch (const std::out_of_range& e)
        {
            log<level::ERR>(
                "Could not look up restriction mode interface from cache");
            return;
        }

        bus->async_method_call(
            [this, index = std::distance(&*std::begin(devices), &dev)](
                boost::system::error_code ec, ipmi::Value v) {
                if (ec)
                {
                    log<level::ERR>("Error in RestrictionMode Get");
                    // Fail-safe to true.
                    restrictedMode[index] = true;
                    return;
                }

                auto mode = std::get<std::string>(v);
                auto restrictionMode =
                    RestrictionMode::convertModesFromString(mode);

                bool restrictMode =
                    (restrictionMode == RestrictionMode::Modes::Whitelist);
                restrictedMode.emplace_back(restrictMode);

                log<level::INFO>((restrictMode ? "Set restrictedMode = true"
                                               : "Set restrictedMode = false"));
            },
            restrictionModeService, restrictionModeSetting,
            "org.freedesktop.DBus.Properties", "Get", restrictionModeIntf,
            "RestrictionMode");
    }
}

/** @brief Update RestrictionMode if any changes in RestrictionMode
 *  @param[in] m - sdbusplus message. Using this to get Updated Mode dbus path
 *  @param[in] deviceList - map to store devices path and their index
 *  @returns void.
 */

void WhitelistFilter::handleRestrictedModeChange(
    sdbusplus::message_t& m, const std::map<std::string, size_t>& deviceList)
{
    using namespace sdbusplus::xyz::openbmc_project::Control::Security::server;
    std::string intf;
    std::vector<std::pair<std::string, ipmi::Value>> propertyList;
    m.read(intf, propertyList);

    std::string path = m.get_path();
    size_t hostId = 0;
    auto it = deviceList.find(path);

    if (it == deviceList.end())
    {
        log<level::ERR>("Key not found in deviceList ");
    }
    else
    {
        hostId = it->second;
    }

    for (const auto& property : propertyList)
    {
        if (property.first == "RestrictionMode")
        {
            RestrictionMode::Modes restrictionMode =
                RestrictionMode::convertModesFromString(
                    std::get<std::string>(property.second));
            bool restrictMode =
                (restrictionMode == RestrictionMode::Modes::Whitelist);
            restrictedMode[hostId] = restrictMode;
            log<level::INFO>((restrictMode ? "Updated restrictedMode = true"
                                           : "Updated restrictedMode = false"));
        }
    }
}

/** @brief Get and Update RestrictionModes of supported devices
 *  @param[in] void
 *  @returns void.
 */

void WhitelistFilter::postInit()
{
    objects = std::make_unique<settings::Objects>(
        *bus, std::vector<settings::Interface>({restrictionModeIntf}));
    if (!objects)
    {
        log<level::ERR>(
            "Failed to create settings object; defaulting to restricted mode");
        return;
    }

    std::vector<std::string> devices;
    try
    {
        devices = objects->map.at(restrictionModeIntf);
    }
    catch (const std::out_of_range& e)
    {
        log<level::ERR>(
            "Could not look up restriction mode interface from cache");
        return;
    }

    // Initialize restricted mode
    cacheRestrictedMode(devices);
    // Wait for changes on Restricted mode
    std::map<std::string, size_t> deviceList;

    for (size_t index = 0; index < devices.size(); index++)
    {
        deviceList.emplace(devices[index], index);
    }

    std::string filterStr;
    std::string devicesDbusPath{"/xyz/openbmc_project/control"};

    filterStr = sdbusplus::bus::match::rules::propertiesChangedNamespace(
        devicesDbusPath, restrictionModeIntf);

    modeChangeMatch = std::make_unique<sdbusplus::bus::match_t>(
        *bus, filterStr, [this, deviceList](sdbusplus::message_t& m) {
            handleRestrictedModeChange(m, deviceList);
        });
}

/** @brief Filter IPMI messages with RestrictedMode
 *  @param[in] request - IPMI messahe request
 *  @returns IPMI completion code success or error.
 */

ipmi::Cc WhitelistFilter::filterMessage(ipmi::message::Request::ptr request)
{
    /* Getting hostIdx for all IPMI devices like hosts, debugcard and other
   devices from ipmi::message::Request and call postInit() to get the
   restriction mode for all the IPMI commands */

    size_t hostIdx = request->ctx->hostIdx;

    if (request->ctx->channel == ipmi::channelSystemIface &&
        restrictedMode[hostIdx])
    {
        if (!std::binary_search(
                whitelist.cbegin(), whitelist.cend(),
                std::make_pair(request->ctx->netFn, request->ctx->cmd)))
        {
            log<level::ERR>("Net function not whitelisted",
                            entry("NETFN=0x%X", int(request->ctx->netFn)),
                            entry("CMD=0x%X", int(request->ctx->cmd)));

            return ipmi::ccInsufficientPrivilege;
        }
    }
    return ipmi::ccSuccess;
}

// instantiate the WhitelistFilter when this shared object is loaded
WhitelistFilter whitelistFilter;

} // namespace

} // namespace ipmi
