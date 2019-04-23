#include "read_fru_data.hpp"

#include "fruread.hpp"

#include <algorithm>
#include <ipmid/api.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <map>
#include <phosphor-logging/elog-errors.hpp>
#include <sdbusplus/message/types.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

extern const FruMap frus;
namespace ipmi
{
namespace fru
{

using namespace phosphor::logging;
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
std::unique_ptr<sdbusplus::bus::match_t> matchPtr
    __attribute__((init_priority(101)));

static constexpr auto INV_INTF = "xyz.openbmc_project.Inventory.Manager";
static constexpr auto OBJ_PATH = "/xyz/openbmc_project/inventory";
static constexpr auto PROP_INTF = "org.freedesktop.DBus.Properties";

namespace cache
{
// User initiate read FRU info area command followed by
// FRU read command. Also data is read in small chunks of
// the specified offset and count.
// Caching the data which will be invalidated when ever there
// is a change in FRU properties.
FRUAreaMap fruMap;
} // namespace cache
/**
 * @brief Read all the property value's for the specified interface
 *  from Inventory.
 *
 * @param[in] intf Interface
 * @param[in] path Object path
 * @return map of properties
 */
ipmi::PropertyMap readAllProperties(const std::string& intf,
                                    const std::string& path)
{
    ipmi::PropertyMap properties;
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    auto service = ipmi::getService(bus, INV_INTF, OBJ_PATH);
    std::string objPath = OBJ_PATH + path;
    auto method = bus.new_method_call(service.c_str(), objPath.c_str(),
                                      PROP_INTF, "GetAll");
    method.append(intf);
    auto reply = bus.call(method);
    if (reply.is_method_error())
    {
        // If property is not found simply return empty value
        log<level::ERR>("Error in reading property values from inventory",
                        entry("INTERFACE=%s", intf.c_str()),
                        entry("PATH=%s", objPath.c_str()));
        return properties;
    }
    reply.read(properties);
    return properties;
}

void processFruPropChange(sdbusplus::message::message& msg)
{
    if (cache::fruMap.empty())
    {
        return;
    }
    std::string path = msg.get_path();
    // trim the object base path, if found at the beginning
    if (path.compare(0, strlen(OBJ_PATH), OBJ_PATH) == 0)
    {
        path.erase(0, strlen(OBJ_PATH));
    }
    for (const auto& [fruId, instanceList] : frus)
    {
        auto found = std::find_if(
            instanceList.begin(), instanceList.end(),
            [&path](const auto& iter) { return (iter.path == path); });

        if (found != instanceList.end())
        {
            cache::fruMap.erase(fruId);
            break;
        }
    }
}

// register for fru property change
int registerCallbackHandler()
{
    if (matchPtr == nullptr)
    {
        using namespace sdbusplus::bus::match::rules;
        sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
        matchPtr = std::make_unique<sdbusplus::bus::match_t>(
            bus,
            path_namespace(OBJ_PATH) + type::signal() +
                member("PropertiesChanged") + interface(PROP_INTF),
            std::bind(processFruPropChange, std::placeholders::_1));
    }
    return 0;
}

/**
 * @brief Read FRU property values from Inventory
 *
 * @param[in] fruNum  FRU id
 * @return populate FRU Inventory data
 */
FruInventoryData readDataFromInventory(const FRUId& fruNum)
{
    auto iter = frus.find(fruNum);
    if (iter == frus.end())
    {
        log<level::ERR>("Unsupported FRU ID ", entry("FRUID=%d", fruNum));
        elog<InternalFailure>();
    }

    FruInventoryData data;
    auto& instanceList = iter->second;
    for (auto& instance : instanceList)
    {
        for (auto& intf : instance.interfaces)
        {
            ipmi::PropertyMap allProp =
                readAllProperties(intf.first, instance.path);
            for (auto& properties : intf.second)
            {
                auto iter = allProp.find(properties.first);
                if (iter != allProp.end())
                {
                    data[properties.second.section].emplace(
                        properties.first, std::move(std::get<std::string>(
                                              allProp[properties.first])));
                }
            }
        }
    }
    return data;
}

const FruAreaData& getFruAreaData(const FRUId& fruNum)
{
    auto iter = cache::fruMap.find(fruNum);
    if (iter != cache::fruMap.end())
    {
        return iter->second;
    }
    auto invData = readDataFromInventory(fruNum);

    // Build area info based on inventory data
    FruAreaData newdata = buildFruAreaData(std::move(invData));
    cache::fruMap.emplace(fruNum, std::move(newdata));
    return cache::fruMap.at(fruNum);
}
} // namespace fru
} // namespace ipmi
