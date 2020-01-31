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
    void cacheRestrictedMode();
    void handleRestrictedModeChange(sdbusplus::message::message& m);
    void updateRestrictionMode(const std::string& value);
    ipmi::Cc filterMessage(ipmi::message::Request::ptr request);

    sdbusplus::xyz::openbmc_project::Control::Security::server::
        RestrictionMode::Modes restrictionMode =
            sdbusplus::xyz::openbmc_project::Control::Security::server::
                RestrictionMode::Modes::ProvisionedHostWhitelist;
    std::shared_ptr<sdbusplus::asio::connection> bus;
    std::unique_ptr<sdbusplus::bus::match::match> modeChangeMatch;
    std::unique_ptr<sdbusplus::bus::match::match> modeIntfAddedMatch;

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

void WhitelistFilter::cacheRestrictedMode()
{
    using namespace sdbusplus::xyz::openbmc_project::Control::Security::server;
    std::string restrictionModeSetting;
    std::string restrictionModeService;
    try
    {
        auto objects = settings::Objects(
            *bus, std::vector<settings::Interface>({restrictionModeIntf}));
        restrictionModeSetting = objects.map.at(restrictionModeIntf).at(0);
        restrictionModeService =
            objects.service(restrictionModeSetting, restrictionModeIntf);
    }
    catch (const std::out_of_range& e)
    {
        log<level::INFO>(
            "Could not initialize provisioning mode, defaulting to restricted");
        return;
    }
    catch (const std::exception&)
    {
        log<level::INFO>(
            "Could not initialize provisioning mode, defaulting to restricted");
        return;
    }

    bus->async_method_call(
        [this](boost::system::error_code ec, ipmi::Value v) {
            if (ec)
            {
                log<level::INFO>("Could not initialize provisioning mode, "
                                 "defaulting to restricted");
                return;
            }
            auto mode = std::get<std::string>(v);
            restrictionMode = RestrictionMode::convertModesFromString(mode);
            log<level::INFO>(
                "Read restriction mode",
                entry("VALUE=%d", static_cast<int>(restrictionMode)));
        },
        restrictionModeService, restrictionModeSetting,
        "org.freedesktop.DBus.Properties", "Get", restrictionModeIntf,
        "RestrictionMode");
}

void WhitelistFilter::updateRestrictionMode(const std::string& value)
{
    restrictionMode = sdbusplus::xyz::openbmc_project::Control::Security::
        server::RestrictionMode::convertModesFromString(value);
    log<level::INFO>("Updated restriction mode",
                     entry("VALUE=%d", static_cast<int>(restrictionMode)));
}

void WhitelistFilter::handleRestrictedModeChange(sdbusplus::message::message& m)
{
    using namespace sdbusplus::xyz::openbmc_project::Control::Security::server;
    std::string signal = m.get_member();
    if (signal == "PropertiesChanged")
    {
        std::string intf;
        std::vector<std::pair<std::string, ipmi::Value>> propertyList;
        m.read(intf, propertyList);
        for (const auto& property : propertyList)
        {
            if (property.first == "RestrictionMode")
            {
                updateRestrictionMode(std::get<std::string>(property.second));
            }
        }
    }
    else if (signal == "InterfacesAdded")
    {
        sdbusplus::message::object_path path;
        DbusInterfaceMap restModeObj;
        m.read(path, restModeObj);
        auto intfItr = restModeObj.find(restrictionModeIntf);
        if (intfItr == restModeObj.end())
        {
            return;
        }
        PropertyMap& propertyList = intfItr->second;
        auto itr = propertyList.find("RestrictionMode");
        if (itr == propertyList.end())
        {
            return;
        }
        updateRestrictionMode(std::get<std::string>(itr->second));
    }
}

void WhitelistFilter::postInit()
{
    // Wait for changes on Restricted mode
    namespace rules = sdbusplus::bus::match::rules;
    const std::string filterStrModeChange =
        rules::type::signal() + rules::member("PropertiesChanged") +
        rules::interface("org.freedesktop.DBus.Properties") +
        rules::argN(0, restrictionModeIntf);

    const std::string filterStrModeIntfAdd =
        rules::interfacesAdded() +
        rules::argNpath(
            0, "/xyz/openbmc_project/control/security/restriction_mode");

    modeChangeMatch = std::make_unique<sdbusplus::bus::match::match>(
        *bus, filterStrModeChange, [this](sdbusplus::message::message& m) {
            handleRestrictedModeChange(m);
        });
    modeIntfAddedMatch = std::make_unique<sdbusplus::bus::match::match>(
        *bus, filterStrModeIntfAdd, [this](sdbusplus::message::message& m) {
            handleRestrictedModeChange(m);
        });

    // Initialize restricted mode
    cacheRestrictedMode();
}

ipmi::Cc WhitelistFilter::filterMessage(ipmi::message::Request::ptr request)
{
    using namespace sdbusplus::xyz::openbmc_project::Control::Security::server;

    if (request->ctx->channel == ipmi::channelSystemIface &&
        (restrictionMode != RestrictionMode::Modes::None &&
         restrictionMode != RestrictionMode::Modes::Provisioning))
    {
        switch (restrictionMode)
        {
            case RestrictionMode::Modes::ProvisionedHostWhitelist:
            {
                if (!std::binary_search(
                        whitelist.cbegin(), whitelist.cend(),
                        std::make_pair(request->ctx->netFn, request->ctx->cmd)))
                {
                    log<level::ERR>(
                        "Net function not whitelisted",
                        entry("NETFN=0x%X", int(request->ctx->netFn)),
                        entry("CMD=0x%X", int(request->ctx->cmd)));
                    return ipmi::ccInsufficientPrivilege;
                }
                break;
            }
            default: // for whitelist, blacklist & HostDisabled
                return ipmi::ccInsufficientPrivilege;
        }
    }
    return ipmi::ccSuccess;
}

// instantiate the WhitelistFilter when this shared object is loaded
WhitelistFilter whitelistFilter;

} // namespace

} // namespace ipmi
