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

constexpr auto mapperService = "xyz.openbmc_project.ObjectMapper";
constexpr auto mapperPath = "/xyz/openbmc_project/object_mapper";
constexpr auto mapperIntf = "xyz.openbmc_project.ObjectMapper";

Objects::Objects(sdbusplus::bus_t& bus, const std::vector<Interface>& filter) :
    bus(bus)
{
    ipmi::ObjectTree objectTree;
    try
    {
        objectTree = ipmi::getSubTree(bus, filter, root);
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("Failed to call the getSubTree method.",
                        entry("ERROR=%s", e.what()));
        elog<InternalFailure>();
    }

    for (auto& iter : objectTree)
    {
        const auto& path = iter.first;
        for (auto& interface : iter.second.begin()->second)
        {
            auto found = map.find(interface);
            if (map.end() != found)
            {
                auto& paths = found->second;
                paths.push_back(path);
            }
            else
            {
                map.emplace(std::move(interface), std::vector<Path>({path}));
            }
        }
    }
}

Service Objects::service(const Path& path, const Interface& interface) const
{
    using Interfaces = std::vector<Interface>;
    auto mapperCall = bus.new_method_call(mapperService, mapperPath, mapperIntf,
                                          "GetObject");
    mapperCall.append(path);
    mapperCall.append(Interfaces({interface}));

    std::map<Service, Interfaces> result;
    try
    {
        auto response = bus.call(mapperCall);
        response.read(result);
        return result.begin()->first;
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("Invalid response from mapper",
                        entry("ERROR=%s", e.what()));
        elog<InternalFailure>();
    }
}

} // namespace settings
