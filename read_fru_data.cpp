#include <map>
#include <phosphor-logging/elog-errors.hpp>
#include <iostream>
#include "xyz/openbmc_project/Common/error.hpp"
#include "read_fru_data.hpp"
#include "fruread.hpp"
#include "host-ipmid/ipmid-api.h"
#include "utils.hpp"


extern const FruMap frus;
using namespace phosphor::logging;
using InternalFailure =
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
using namespace sdbusplus::bus::match::rules;

namespace ipmi
{
namespace fru 
{
static constexpr auto INV_INTF  = "xyz.openbmc_project.Inventory.Manager";
static constexpr auto OBJ_PATH  = "/xyz/openbmc_project/inventory";
static constexpr auto PROP_INTF = "org.freedesktop.DBus.Properties";

constexpr auto INVENTORY_SETTINGS_CHANGE =
        "type='signal',interface='org.freedesktop.DBus.Properties',"
        "path_namespace='/xyz/openbmc_project/inventory',"
        "member='PropertiesChanged'";

using Property = std::string;
using Value = std::string;

FrusAreaMap gfrusMap;
/**
 * @brief Read the property value from Inventory
 *
 * @param[in] bus dbus
 * @param[in] intf Interface
 * @param[in] propertyName Name of the property
 * @param[in] path Object path
 * @return property value
 */
std::string readProperty(
        sdbusplus::bus::bus& bus, const std::string& intf,
        const std::string& propertyName, const std::string& path)
{
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
    return value;
}

//process fru property change signal
int processFruPropChange(sd_bus_message* m, void* userdata, sd_bus_error* ret)
{
    if(gfrusMap.size() <= 0)
    {
        return 0;
    }
    std::string path = sd_bus_message_get_path(m);
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
            gfrusMap.erase(fruId);
            break;
        }
    }
    return 0;
}

//register for fru property change
int registerFruPropertyChangeHandle()
{
    int r(0);
    auto bus = ipmid_get_sd_bus_connection();
    r = sd_bus_add_match(
        bus, NULL, INVENTORY_SETTINGS_CHANGE, processFruPropChange, NULL);
    if (r < 0)
    {
        log<level::ERR>("Failure in adding property change listener");
    }
    return r;
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
FruInventoryData readDataFromInventory(
    sdbusplus::bus::bus& bus, const uint8_t& fruNum)
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
                        bus, interfaceList.first, properties.first,
                        instance.first);
                data.emplace_back(std::make_tuple(pdata.section,
                    properties.first, value));
            }
        }
    }
    return data;
}

FruAreaData getFruAreaData(sdbusplus::bus::bus& bus, const uint8_t& fruNum)
{
    auto iter = gfrusMap.find(fruNum);
    if (iter != gfrusMap.end())
    {
        return iter->second;
    }
    auto invData = readDataFromInventory(bus, fruNum);

    //Build area info based on inventory data
    FruAreaData data = buildFruAreaData(invData);
    gfrusMap.insert(std::pair<uint8_t, FruAreaData>(fruNum, data));
    return data;
}
} //fru
} //ipmi
