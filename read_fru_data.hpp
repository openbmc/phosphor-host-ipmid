#pragma once
#include <map>
#include <string>
#include <sdbusplus/bus.hpp>
#include "ipmi_fru_info_area.hpp"
namespace phosphor 
{
namespace hostipmi
{
namespace details
{
using FrusAreaMap = std::map<uint8_t, FruAreaData>;
using Property = std::string;
using Value = std::string;
} //details

/** @class ReadFruData
 *  @brief Handles IPMI Fru Read and Fru Read Info commands
 */
class ReadFruData
{

    public:
        ReadFruData() {};
        /** @brief Only need the default ReadFruData */
        ReadFruData(const ReadFruData&) = delete;
        ReadFruData& operator=(const ReadFruData&) = delete;
        ReadFruData(ReadFruData&&) = delete;
        ReadFruData& operator=(ReadFruData&&) = delete;

        FruAreaData getFruAreaData(const uint8_t& fruNum);
    private:
        FruInventoryData readDataFromInventory(const uint8_t& fruNum);

        std::string readProperty(
            const std::string& intf, const std::string& propertyName,
            const std::string& path);
    
        details::FrusAreaMap _frusMap;
};
} //hostipmi
} //phosphor