#include <algorithm>
#include <array>
#include <iostream>
#include <ipmi/ipmi-api.hpp>
#include <ipmiwhitelist.hpp>
#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog-errors.hpp>
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

  restrictedMode = false;

  using namespace sdbusplus::xyz::openbmc_project::Control::Security::server;
  const auto& restrictionModeSetting =
    internal::cache::objects->map.at(internal::restrictionModeIntf).front();
  bus->async_method_call([](boost::system::error_code ec, std::string mode)
      {
      std::cerr << __FUNCTION__ << ':' << __LINE__ << "\n";
        if (ec) {
          // log<level::ERR>("Error in RestrictionMode Get");
          std::cerr << "Error in RestrictionMode Get\n";
          // Fail-safe to true.
          restrictedMode = true;
          return;
        }
        auto restrictionMode = RestrictionMode::convertModesFromString(mode);
        restrictedMode = (RestrictionMode::Modes::Whitelist == restrictionMode);
        std::cerr << "updated restrictedMode = "
                  << std::boolalpha << restrictedMode << '\n';
      },
      internal::cache::objects->service(restrictionModeSetting,
        internal::restrictionModeIntf).c_str(),
      restrictionModeSetting.c_str(),
      "org.freedesktop.DBus.Properties",
      "Get", "RestrictionMode");
}
static void handleRestrictedModeChange(sdbusplus::message::message& m)
{
  using namespace sdbusplus::xyz::openbmc_project::Control::Security::server;
  std::string mode;
  m.read(mode);
  auto restrictionMode = RestrictionMode::convertModesFromString(mode);
  restrictedMode = (RestrictionMode::Modes::Whitelist == restrictionMode);
  std::cerr << "updated restrictedMode = "
            << std::boolalpha << restrictedMode << '\n';
}
static std::unique_ptr<sdbusplus::bus::match::match> modeChangeMatch;
static void postInit()
{
  auto bus = getSdBus();

try{
  internal::cache::objects = std::make_unique<settings::Objects>(
      *bus,
      std::vector<settings::Interface>({internal::restrictionModeIntf}));

  // Initialize restricted mode
   cacheRestrictedMode();
  // Wait for changes on Restricted mode
  std::string filterStr =
    sdbusplus::bus::match::rules::propertiesChanged(
        internal::cache::objects->map.at(internal::restrictionModeIntf).front(),
        internal::restrictionModeIntf);
  modeChangeMatch.reset(new sdbusplus::bus::match::match(
      *bus, filterStr, handleRestrictedModeChange));
} catch(...) { std::cerr << "failed to cache mode\n"; }
}

ipmi::Cc whitelistFilter(ipmi::message::Request::ptr request)
{
  std::cerr << __FUNCTION__ << " check request "
    << int(request->ctx->netFn) << '/'
    << int(request->ctx->cmd) << " (channel "
    << int(request->ctx->channel) << ")\n";

  if (restrictedMode)
  {
    if (!std::binary_search(whitelist.cbegin(), whitelist.cend(),
          std::make_pair(request->ctx->netFn, request->ctx->cmd)))
    {
      /*
      log<level::ERR>("Net function not whitelisted",
          entry("NETFN=0x%X", netfn),
          entry("CMD=0x%X", cmd));
      */
      std::cerr << "NetFn/Cmd not whitelisted ("
        << int(request->ctx->netFn) << '/' << int(request->ctx->cmd) << ")\n";
      return ipmi::ccInsufficientPrivilege;
    }
  }
  return ipmi::ccSuccess;
}

void whitelistFilterInit()
{
  log<level::INFO>("Loading whitelist filter");

  ipmi::registerFilter(ipmi::prioOpenBmcBase, whitelistFilter);

  post_work(postInit);

  std::cerr << __FUNCTION__ << " done\n";
}

