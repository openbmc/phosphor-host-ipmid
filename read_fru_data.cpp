#include<iostream>
#include "read_fru_data.hpp"
#include "fruread.hpp"
#include "host-ipmid/ipmid-api.h"
#include "utils.hpp"

namespace phosphor 
{
namespace hostipmi
{

extern const FruMap frus;

FruAreaData ReadFruData::getFruAreaData(const uint8_t& fruNum) 
{
    //If data already exist return it
    auto iter = _frusMap.find(fruNum);
    if (iter != _frusMap.end())
    {
        return iter->second;
    }

    auto invData = readDataFromInventory(fruNum);
    if (invData.empty())
    {
        throw std::runtime_error("Failed to read Inventory data for FRUS " +
                fruNum);
    }

    //Build area info based on inventory data
    auto areadData = buildFruAreaData(invData);
    if (areadData.empty())
    {
        throw std::runtime_error("Failed to create FRU info area for FRU " +
                fruNum);
    }
    _frusMap.insert(std::pair<uint8_t, FruAreaData>(fruNum, areadData));
    return areadData;
}

/**
 * @brief Helper function to read a property
 *
 * @param[in] intf- the interface the property is on
 * @param[in] propertName - the name of the property
 * @param[in] path - the dbus path
 * @param[in] service - the dbus service
 * @param[in] bus - the dbus object
 * @param[out] value - filled in with the property value
 */
std::string readProperty(
        const std::string& intf, const std::string& propertyName,
        const std::string& path)
{
    std::string value;
    try
    {
        constexpr auto PROPERTY_INTF = "org.freedesktop.DBus.Properties";
        sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
        auto service = ipmi::getService(bus, intf, path);
        auto method = bus.new_method_call(service.c_str(),
                                           path.c_str(),
                                           PROPERTY_INTF,
                                           "Get");
        method.append(intf, propertyName);
        auto reply = bus.call(method);
        if (reply.is_method_error())
        {
            throw std::runtime_error(
                "Error in property get call for path " + path);
        }
        sdbusplus::message::variant<std::string> property;
        reply.read(property);
        value = sdbusplus::message::variant_ns::get<std::string>(property);
    }
    catch (std::exception& e)
    {
        std::cerr << "exception " << e.what() << "\n";
    }
    return value;
}

//------------------------------------------------------------------------
// Takes FRU data, invokes Parser for each fru record area and updates
// Inventory
//------------------------------------------------------------------------
FruInventoryData ReadFruData::readDataFromInventory(
        const uint8_t& fruNum)
{
    std::cout << "DEVENDER readDataFromInventory fruid " << fruNum << std::endl;
    auto iter = frus.find(fruNum);
    if (iter == frus.end())
    {
        std::cerr << "ERROR Unable to get the fru info for FRU="
                  << static_cast<int>(fruNum) << "\n";
        throw std::runtime_error("Invalid fru number " + fruNum);
    }

    auto& instanceList = iter->second;
    if (instanceList.size() <= 0)
    {
        std::cout << "Object List empty for this FRU="
                  << static_cast<int>(fruNum) << "\n";
    }

    FruInventoryData data;
    for (auto& instance : instanceList)
    {
        std::cout << "DEVENDER ipmi_update_inventory instance path " << instance.first << std::endl;
        for (auto& interfaceList : instance.second)
        {
            std::cout << "DEVENDER ipmi_update_inventory interface path " << interfaceList.first << std::endl;
            for (auto& properties : interfaceList.second)
            {
                decltype(auto) pdata = properties.second;
                auto value = readProperty(
                    interfaceList.first, properties.first, instance.first);
                data.emplace_back(std::make_tuple(pdata.section, 
                    properties.first, value));
            }
        }
    }
    return data;
}

} //hostipmi
} //phosphor