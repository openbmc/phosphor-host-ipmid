#include <mapper.h>
#include <string.h>
#include <bitset>
#include "host-ipmid/ipmid-api.h"
#include <phosphor-logging/log.hpp>
#include "types.hpp"
#include "utils.hpp"

extern int updateSensorRecordFromSSRAESC(const void *);
extern sd_bus *bus;

namespace ipmi
{
namespace sensor
{

using namespace phosphor::logging;

uint8_t getValue(uint8_t offset,SetSensorReadingReq *cmd)
{
    if (offset == 0x0)
    {
        return 0;
    }
    if(offset == 0x1)
    {
        return cmd->eventData1;
    }
    if(offset == 0x2)
    {
        return cmd->eventData2;
    }
    if (offset == 0x3)
    {
        return cmd->eventData3;
    }
    if (offset == 0xFF)
    {
        return cmd->reading;
    }
    return 0;
}

uint8_t setInventorySensorReading(SetSensorReadingReq *cmdData,
                                     Info &sensorInfo)
{

    auto assertionStates =
            (static_cast<uint16_t>(cmdData->assertOffset8_14)) << 8 |
            cmdData->assertOffset0_7;

    auto deassertionStates =
            (static_cast<uint16_t>(cmdData->deassertOffset8_14)) << 8 |
            cmdData->deassertOffset0_7;

    std::bitset<16> assertionSet(assertionStates);
    std::bitset<16> deassertionSet(deassertionStates);
    auto& interfaceList = sensorInfo.sensorInterfaces;
    if (interfaceList.empty())
    {
        log<level::ERR>("Interface List empty for the sensor",
                entry("Sensor Number = %d", cmdData->number));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    ipmi::sensor::ObjectMap objects;
    ipmi::sensor::InterfaceMap interfaces;
    for (const auto& interface : interfaceList)
    {
        for (const auto& property : interface.second)
        {
            ipmi::sensor::PropertyMap props;
            bool valid = false;
            for (const auto& value : property.second)
            {
                if (assertionSet.test(value.first))
                {
                    props.emplace(property.first, value.second.assert);
                    valid = true;
                }
                else if (deassertionSet.test(value.first))
                {
                    props.emplace(property.first, value.second.deassert);
                    valid = true;
                }
            }
            if (valid)
            {
                interfaces.emplace(interface.first, std::move(props));
            }
        }
    }
    objects.emplace(sensorInfo.sensorPath, std::move(interfaces));
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    using namespace std::string_literals;
    auto& intf = sensorInfo.updateInterface;
    auto& path = sensorInfo.updatePath;
    std::string service;

    try
    {
        service = ipmi::getService(bus, intf, path);

        // Update the inventory manager
        auto pimMsg = bus.new_method_call(service.c_str(),
                                          path.c_str(),
                                          intf.c_str(),
                                          "Notify");
        pimMsg.append(std::move(objects));
        auto inventoryMgrResponseMsg = bus.call(pimMsg);
        if (inventoryMgrResponseMsg.is_method_error())
        {
            log<level::ERR>("Error in notify call");
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
    }
    catch (const std::runtime_error& e)
    {
        log<level::ERR>(e.what());
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    return IPMI_CC_OK;
}

uint8_t setPropertySensorReading(SetSensorReadingReq *cmdData,
                                    Info &sensorInfo)
{
    auto assertionStates =
            (static_cast<uint16_t>(cmdData->assertOffset8_14)) << 8 |
            cmdData->assertOffset0_7;

    auto deassertionStates =
            (static_cast<uint16_t>(cmdData->deassertOffset8_14)) << 8 |
            cmdData->deassertOffset0_7;

    std::bitset<16> assertionSet(assertionStates);
    std::bitset<16> deassertionSet(deassertionStates);

    auto& interfaceList = sensorInfo.sensorInterfaces;
    if (interfaceList.empty())
    {
        log<level::ERR>("Interface List empty for the sensor",
                entry("Sensor Number = %d", cmdData->number));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    ipmi::sensor::ObjectMap objects;
    ipmi::sensor::InterfaceMap interfaces;
    auto& path = sensorInfo.updatePath;
    auto& intf = sensorInfo.updateInterface;

    auto& rtype = sensorInfo.valueReadingType;

    uint8_t setVal = sensorInfo.getSensorValue(cmdData);

    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    using namespace std::string_literals;
    std::string service;

    try
    {
        service = ipmi::getService(bus, intf, path);
    }
    catch ( const std::runtime_error& e )
    {
        log<level::ERR>(e.what());
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    // Update the value to the respective service
    auto updMsg = bus.new_method_call(service.c_str(),
                                      path.c_str(),
                                      intf.c_str(),
                                      "Set");

    //for each interface in the list
    for ( const auto& interface : interfaceList )
    {
        updMsg.append(interface.first);

        for ( const auto& property : interface.second )
        {
            for ( const auto& value : property.second )
            {
                updMsg.append(property.first);
                //for assertion type check whether bit is set.
                if ( rtype == IPMI_TYPE_ASSERTION )
                {
                    if ( assertionSet.test(value.first) )
                    {
                        updMsg.append(value.second.assert);
                    }
                    else if (deassertionSet.test(value.first))
                    {
                        updMsg.append(value.second.deassert);
                    }
                }
                else if ( rtype == IPMI_TYPE_READING )
                {
                    //if offset is FF then it is reading type
                    if ( 0xFF == value.first )
                    {
                        updMsg.append(setVal);
                    }
                    // for event type if the value at offset match with
                    // key then get the mapped value.
                    else if ( setVal == value.first )
                    {
                        updMsg.append(value.second.assert);
                    }
                }
            }
        }
    }

    try
    {
        auto serviceResponseMsg = bus.call(updMsg);
        if (serviceResponseMsg.is_method_error())
        {
            log<level::ERR>("Error in set call");
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
    }
    catch ( const std::runtime_error& e )
    {
        log<level::ERR>(e.what());
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    return IPMI_CC_OK;
}

}//sensor
}//ipmi
