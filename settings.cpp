#include "settings.hpp"

#include <ipmid/utils.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/message/types.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace settings
{

using namespace phosphor::logging;
using namespace sdbusplus::error::xyz::openbmc_project::common;

Objects::Objects(sdbusplus::bus_t& bus, const std::vector<Interface>& filter) :
    bus(bus)
{
    ipmi::ObjectTree objectTree;
    try
    {
        objectTree = ipmi::getSubTree(bus, filter);
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("Failed to call the getSubTree method.",
                        entry("ERROR=%s", e.what()));
        elog<InternalFailure>();
    }

    for (const auto& [path, serverMappers] : objectTree)
    {
        for (const auto& [service, interfaces] : serverMappers)
        {
            for (const auto& interface : interfaces)
            {
                auto found = std::find_if(
                    filter.begin(), filter.end(),
                    [&](const std::string& intf) { return interface == intf; });

                if (found == filter.end())
                {
                    continue;
                }

                if (settingMaps.contains(interface))
                {
                    std::tuple<std::string, std::string> services =
                        std::make_tuple(service, path);
                    settingMaps.emplace(
                        interface,
                        std::vector<std::tuple<std::string, std::string>>(
                            {std::move(services)}));
                }
                else
                {
                    settingMaps[interface].push_back({service, path});
                }
            }
        }
    }
}

} // namespace settings
