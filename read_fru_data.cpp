#include <map>
#include <phosphor-logging/elog-errors.hpp>
#include "xyz/openbmc_project/Common/error.hpp"
#include "read_fru_data.hpp"
#include "fruread.hpp"
#include "host-ipmid/ipmid-api.h"
#include "utils.hpp"

extern const FruMap frus;
namespace ipmi
{
namespace fru
{
using namespace phosphor::logging;
using InternalFailure =
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
std::unique_ptr<sdbusplus::bus::match_t> matchPtr(nullptr);

static constexpr auto INV_INTF  = "xyz.openbmc_project.Inventory.Manager";
static constexpr auto OBJ_PATH  = "/xyz/openbmc_project/inventory";
static constexpr auto PROP_INTF = "org.freedesktop.DBus.Properties";

namespace cache
{
    //User initiate read FRU info area command followed by
    //FRU read command. Also data is read in small chunks of
    //the specified offset and count.
    //Caching the data which will be invalidated when ever there
    //is a change in FRU properties.
    FRUAreaMap frusMap;
}
/**
 * @brief Read the property value from Inventory
 *
 * @param[in] bus dbus
 * @param[in] intf Interface
 * @param[in] propertyName Name of the property
 * @param[in] path Object path
 * @return property value
 */
std::string readProperty(const std::string& intf,
                         const std::string& propertyName,
                         const std::string& path)
{
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    auto service = ipmi::getService(bus, INV_INTF, OBJ_PATH);
    std::string objPath = OBJ_PATH + path;
    auto method = bus.new_method_call(service.c_str(),
                                       objPath.c_str(),
                                       PROP_INTF,
                                       "Get");
    method.append(intf, propertyName);
    auto reply = bus.call(method);
    if (reply.is_method_error())
    {
        log<level::ERR>("Error in reading property value from inventory",
            entry("Property=%s", propertyName));
        elog<InternalFailure>();
    }
    sdbusplus::message::variant<std::string> property;
    reply.read(property);
    std::string value =
        sdbusplus::message::variant_ns::get<std::string>(property);
    return std::move(value);
}

void processFruPropChange(sdbusplus::message::message& msg)
{
    if(cache::frusMap.size() <= 0)
    {
        return;
    }
    std::string path = std::move(msg.get_path());
    //trim the object base path
    std::size_t found = path.find(OBJ_PATH);
    if (found != std::string::npos)
    {
        path.erase(found, strlen(OBJ_PATH));
    }
    for (auto& fru : frus)
    {
        bool found = false;
        auto& fruId = fru.first;
        auto& instanceList = fru.second;
        for (auto& instance : instanceList)
        {
            if(instance.first == path)
            {
                found = true;
                break;
            }
        }
        if (found)
        {
            cache::frusMap.erase(fruId);
            break;
        }
    }
    return;
}

//register for fru property change
int registerCallbackHandler()
{
    if(matchPtr == nullptr)
    {
        using namespace sdbusplus::bus::match::rules;
        sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
        matchPtr = std::make_unique<sdbusplus::bus::match_t>(
            bus,
            path_namespace(OBJ_PATH) +
            type::signal() +
            member("PropertiesChanged") +
            interface(PROP_INTF),
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
    FruInventoryData data;
    auto iter = frus.find(fruNum);
    if (iter == frus.end())
    {
        log<level::ERR>("Unsupported FRU ID ",entry("FRUID=%d", fruNum));
        elog<InternalFailure>();
    }

    auto& instanceList = iter->second;
    for (auto& instance : instanceList)
    {
        for (auto& interfaceList : instance.second)
        {
            for (auto& properties : interfaceList.second)
            {
                decltype(auto) pdata = properties.second;
                auto value = readProperty(
                        interfaceList.first, properties.first,
                        instance.first);
                data.emplace_back(std::make_tuple(pdata.section,
                    properties.first, value));
            }
        }
    }
    return std::move(data);
}

FruAreaData& getFruAreaData(const FRUId& fruNum)
{
    auto iter = cache::frusMap.find(fruNum);
    if (iter != cache::frusMap.end())
    {
        return iter->second;
    }
    auto invData = readDataFromInventory(fruNum);

    //Build area info based on inventory data
    FruAreaData newdata = buildFruAreaData(std::move(invData));
    cache::frusMap.emplace(std::pair<FRUId, FruAreaData>(
        fruNum, std::move(newdata)));
    return cache::frusMap.at(fruNum);
}
} //fru
} //ipmi
