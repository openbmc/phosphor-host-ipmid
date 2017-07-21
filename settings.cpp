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

Objects::Objects(sdbusplus::bus::bus& bus)
{
    std::vector<std::string> settingsIntfs =
        {bootModeIntf, bootSourceIntf, restrictionModeIntf, powerRestoreIntf};
    auto depth = 0;

    auto mapperCall = bus.new_method_call(mapperService,
                                          mapperPath,
                                          mapperIntf,
                                          "GetSubTree");
    mapperCall.append(root);
    mapperCall.append(depth);
    mapperCall.append(settingsIntfs);
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

    for (const auto& iter : result)
    {
        const Path& path = iter.first;
        const Service& service = iter.second.begin()->first;
        const Interface& interface = iter.second.begin()->second[0];
        map.emplace(interface, std::make_pair(path, service));
    }
}

} // namespace settings
