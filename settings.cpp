#include "settings.hpp"

#include <ipmid/utils.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/message/types.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace settings
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

constexpr auto mapperService = "xyz.openbmc_project.ObjectMapper";
constexpr auto mapperPath = "/xyz/openbmc_project/object_mapper";
constexpr auto mapperIntf = "xyz.openbmc_project.ObjectMapper";

Objects::Objects(sdbusplus::bus::bus& bus,
                 const std::vector<Interface>& filter) :
    bus(bus)
{
    auto depth = 0;

    auto mapperCall = bus.new_method_call(mapperService, mapperPath, mapperIntf,
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
    auto mapperCall =
        bus.new_method_call(mapperService, mapperPath, mapperIntf, "GetObject");
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

namespace boot
{

std::tuple<Path, OneTimeEnabled> setting(const Objects& objects,
                                         const Interface& iface)
{
    constexpr auto ambiguousOperationCount = 2;
    constexpr auto oneTime = "one_time";
    constexpr auto enabledIntf = "xyz.openbmc_project.Object.Enable";
    bool oneTimeEnabled = false;

    const std::vector<Path>& paths = objects.map.at(iface);
    auto count = paths.size();
    if (!count)
    {
        // If there are no objects implementing the requested interface,
        // that must be an error.
        log<level::ERR>("Interface objects not found",
                        entry("INTERFACE=%s", iface.c_str()));
        elog<InternalFailure>();
    }
    else if (count < ambiguousOperationCount)
    {
        // On the contrary, if there is just one object, that may mean
        // that this particular interface doesn't support one-time
        // setting mode (e.g. Boot Initiator Mailbox).
        // That is not an error, just return the regular setting.
        // If there's just one object, that's the only kind of setting
        // mode this interface supports, so just return that setting path.
        const Path& regularSetting = paths[0];
        return std::make_tuple(regularSetting, oneTimeEnabled);
    }
    else if (count > ambiguousOperationCount)
    {
        // Something must be wrong if there are more objects than expected
        log<level::ERR>("Exactly 1 or 2 interface objects are required",
                        entry("INTERFACE=%s", iface.c_str()),
                        entry("COUNT=%d", count));
        elog<InternalFailure>();
    }

    // We are here because there were exactly two objects implementing the
    // same interface. Take those two and find out which of them is the
    // one-time setting, consider the other the persistent setting.
    size_t index = 0;
    if (std::string::npos == paths[0].rfind(oneTime))
    {
        index = 1;
    }
    const Path& oneTimeSetting = paths[index];
    const Path& regularSetting = paths[!index];

    // Now see if the one-time setting is enabled and return the path for it
    // if so. Otherwise return the path for the persistent setting.
    auto method = objects.bus.new_method_call(
        objects.service(oneTimeSetting, iface).c_str(), oneTimeSetting.c_str(),
        ipmi::PROP_INTF, "Get");
    method.append(enabledIntf, "Enabled");
    auto reply = objects.bus.call(method);
    if (reply.is_method_error())
    {
        log<level::ERR>("Error in getting Enabled property",
                        entry("OBJECT=%s", oneTimeSetting.c_str()),
                        entry("INTERFACE=%s", iface.c_str()));
        elog<InternalFailure>();
    }

    std::variant<bool> enabled;
    reply.read(enabled);
    oneTimeEnabled = std::get<bool>(enabled);
    const Path& setting = oneTimeEnabled ? oneTimeSetting : regularSetting;
    return std::make_tuple(setting, oneTimeEnabled);
}

} // namespace boot

} // namespace settings
