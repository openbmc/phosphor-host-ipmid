#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include "xyz/openbmc_project/Common/error.hpp"
#include "settings.hpp"

namespace settings
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

constexpr auto mapperService = "xyz.openbmc_project.ObjectMapper";
constexpr auto mapperPath = "/xyz/openbmc_project/object_mapper";
constexpr auto mapperIntf = "xyz.openbmc_project.ObjectMapper";

Objects::Objects(sdbusplus::bus::bus& bus,
                 const std::vector<Interface>& filter):
    bus(bus)
{
    auto depth = 0;

    auto mapperCall = bus.new_method_call(mapperService,
                                          mapperPath,
                                          mapperIntf,
                                          "GetSubTree");
    mapperCall.append(root);
    mapperCall.append(depth);
    mapperCall.append(filter);
    auto response = bus.call(mapperCall);
    if (response.is_method_error())
    {
        log<level::ERR>("Error in mapper GetSubTree");
        elog<InternalFailure>();
    }

    using Interfaces = std::vector<Interface>;
    using MapperResponse = std::map<Path, std::map<Service, Interfaces>>;
    MapperResponse result;
    response.read(result);
    if (result.empty())
    {
        log<level::ERR>("Invalid response from mapper");
        elog<InternalFailure>();
    }

    for (auto& iter : result)
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
    auto mapperCall = bus.new_method_call(mapperService,
                                          mapperPath,
                                          mapperIntf,
                                          "GetObject");
    mapperCall.append(path);
    mapperCall.append(Interfaces({interface}));

    auto response = bus.call(mapperCall);
    if (response.is_method_error())
    {
        log<level::ERR>("Error in mapper GetObject");
        elog<InternalFailure>();
    }

    std::map<Service, Interfaces> result;
    response.read(result);
    if (result.empty())
    {
        log<level::ERR>("Invalid response from mapper");
        elog<InternalFailure>();
    }

    return result.begin()->first;
}

} // namespace settings
