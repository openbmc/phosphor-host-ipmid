#include <algorithm>
#include <array>
#include <iostream>
#include <ipmi/ipmi-api.hpp>
#include <ipmi/registration.hpp>
#include <ipmiwhitelist.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <settings.hpp>
#include <xyz/openbmc_project/Control/Security/RestrictionMode/server.hpp>

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
void whitelistFilterInit() __attribute__((constructor));

static bool restrictedMode = true;

namespace internal
{

static constexpr auto restrictionModeIntf =
    "xyz.openbmc_project.Control.Security.RestrictionMode";

namespace cache
{

static std::unique_ptr<settings::Objects> objects = nullptr;

} // namespace cache
} // namespace internal

static void cacheRestrictedMode()
{
    auto bus = getSdBus();

    using namespace sdbusplus::xyz::openbmc_project::Control::Security::server;
    const auto& restrictionModeSetting =
        internal::cache::objects->map.at(internal::restrictionModeIntf).front();
    bus->async_method_call(
        [](boost::system::error_code ec, std::string mode) {
            if (ec)
            {
                log<level::ERR>("Error in RestrictionMode Get");
                // Fail-safe to true.
                restrictedMode = true;
                return;
            }
            auto restrictionMode =
                RestrictionMode::convertModesFromString(mode);
            restrictedMode =
                (RestrictionMode::Modes::Whitelist == restrictionMode);
            if (restrictedMode)
            {
                log<level::INFO>("Set restrictedMode = true");
            }
            else
            {
                log<level::INFO>("Set restrictedMode = false");
            }
        },
        internal::cache::objects
            ->service(restrictionModeSetting, internal::restrictionModeIntf)
            .c_str(),
        restrictionModeSetting.c_str(), "org.freedesktop.DBus.Properties",
        "Get", "RestrictionMode");
}

static void handleRestrictedModeChange(sdbusplus::message::message& m)
{
    using namespace sdbusplus::xyz::openbmc_project::Control::Security::server;
    std::string mode;
    m.read(mode);
    auto restrictionMode = RestrictionMode::convertModesFromString(mode);
    restrictedMode = (RestrictionMode::Modes::Whitelist == restrictionMode);
    if (restrictedMode)
    {
        log<level::INFO>("Updated restrictedMode = true");
    }
    else
    {
        log<level::INFO>("Updated restrictedMode = false");
    }
}
static std::unique_ptr<sdbusplus::bus::match::match> modeChangeMatch;
static void postInit()
{
    auto bus = getSdBus();

    internal::cache::objects = std::make_unique<settings::Objects>(
        *bus,
        std::vector<settings::Interface>({internal::restrictionModeIntf}));

    // Initialize restricted mode
    cacheRestrictedMode();
    // Wait for changes on Restricted mode
    std::string filterStr = sdbusplus::bus::match::rules::propertiesChanged(
        internal::cache::objects->map.at(internal::restrictionModeIntf).front(),
        internal::restrictionModeIntf);
    modeChangeMatch.reset(new sdbusplus::bus::match::match(
        *bus, filterStr, handleRestrictedModeChange));
}

ipmi::Cc whitelistFilter(ipmi::message::Request::ptr request)
{
    /*
    log<level::DEBUG>("whitelist check",
                      entry("CHANNEL=0x%X", int(request->ctx->channel)),
                      entry("NETFN=0x%X", int(request->ctx->netFn)),
                      entry("CMD=0x%X", int(request->ctx->cmd)));
    */

    if (request->ctx->channel == ipmi::channelSystemIface && restrictedMode)
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

void whitelistFilterInit()
{
    log<level::INFO>("Loading whitelist filter");

    ipmi::registerFilter(ipmi::prioOpenBmcBase, whitelistFilter);

    // wait until io->run is going to fetch RestrictionMode
    post_work(postInit);
}
