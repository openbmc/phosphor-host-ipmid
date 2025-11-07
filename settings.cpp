#include "settings.hpp"

#include <ipmid/utils.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/message/types.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/ObjectMapper/common.hpp>

using ObjectMapper = sdbusplus::common::xyz::openbmc_project::ObjectMapper;

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
        lg2::error("Failed to call the getSubTree method: {ERROR}", "ERROR", e);
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
    auto mapperCall = bus.new_method_call(
        ObjectMapper::default_service, ObjectMapper::instance_path,
        ObjectMapper::interface, "GetObject");
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
        lg2::error("Invalid response from mapper: {ERROR}", "ERROR", e);
        elog<InternalFailure>();
    }
}

} // namespace settings
