## This file is a template.  The comment below is emitted
## into the rendered file; feel free to edit this file.

// !!! WARNING: This is a GENERATED Code..Please do NOT Edit !!!

#include <string.h>
#include <bitset>
#include "types.hpp"
#include "host-ipmid/ipmid-api.h"
#include <phosphor-logging/log.hpp>

using namespace ipmi::sensor;
using namespace phosphor::logging;

constexpr auto MAPPER_BUSNAME = "xyz.openbmc_project.ObjectMapper";
constexpr auto MAPPER_PATH = "/xyz/openbmc_project/object_mapper";
constexpr auto MAPPER_INTERFACE = "xyz.openbmc_project.ObjectMapper";

using namespace phosphor::logging;
using DbusInfo = std::pair<std::string,std::string>;
DbusInfo getDbusInfo(sdbusplus::bus::bus& bus,std::string interface)
{
    auto depth = 0;
    auto mapperCall = bus.new_method_call(MAPPER_BUSNAME,
                                          MAPPER_PATH,
                                          MAPPER_INTERFACE,
                                          "GetSubTree");
    mapperCall.append("/");
    mapperCall.append(depth);
    mapperCall.append(std::vector<std::string>({interface}));

    auto mapperResponseMsg = bus.call(mapperCall);
    if (mapperResponseMsg.is_method_error())
    {
        throw std::runtime_error("ERROR in mapper call");
    }

    using MapperResponseType = std::map<std::string,
                               std::map<std::string, std::vector<std::string>>>;
    MapperResponseType mapperResponse;
    mapperResponseMsg.read(mapperResponse);
    if (mapperResponse.empty())
    {
        throw std::runtime_error("Invalid response from mapper");
    }

    auto path = mapperResponse.begin()->first;
    auto service = mapperResponse.begin()->second.begin()->first;
    return std::make_pair(path,service);
}

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

uint8_t setPropertySensorReading(SetSensorReadingReq *cmdData,
                                   Info sensorInfo)
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
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    auto& intf = sensorInfo.updateInterface;

    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    using namespace std::string_literals;
    std::string service;

    //for each interface in the list
    for ( const auto& interface : interfaceList )
    {
        DbusInfo service;

        try
        {
            service = getDbusInfo(bus,interface.first);
        }
        catch ( const std::runtime_error& e )
        {
            log<level::ERR>(e.what());
            return IPMI_CC_UNSPECIFIED_ERROR;
        }

        // Update the value to the respective service
        auto updMsg = bus.new_method_call(service.second.c_str(),
                                      service.first.c_str(),
                                      intf.c_str(),
                                      "Set");

        updMsg.append(interface.first);

        for ( const auto& property : interface.second )
        {
            updMsg.append(property.first);
            for ( const auto& value : property.second )
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
    }
    return IPMI_CC_OK;
}

uint8_t setInventorySensorReading(SetSensorReadingReq *cmdData,
                                     Info sensorInfo)
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
    std::string service;

    try
    {
        auto service = getDbusInfo(bus, intf);

        // Update the inventory manager
        auto pimMsg = bus.new_method_call(service.second.c_str(),
                                          service.first.c_str(),
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

extern const IdInfoMap sensors = {
% for key in sensorDict.iterkeys():
   % if key:
{${key},{
<%
       sensor = sensorDict[key]
       interfaces = sensor["interfaces"]
       path = sensor["path"]
       sensorType = sensor["sensorType"]
       readingType = sensor["sensorReadingType"]
       multiplier = sensor.get("multiplierM", 1)
       offset = sensor.get("offsetB", 0)
       exp = sensor.get("bExp", 0)
       updateInterface = sensor["updateInterface"]
       valueReadingType = sensor["readingType"]
       byteOffset = sensor["byteOffset"]
       if updateInterface == "org.freedesktop.DBus.Properties":
           updateFunc = "setPropertySensorReading"
       elif updateInterface == "xyz.openbmc_project.Inventory.Manager":
           updateFunc = "setInventorySensorReading"
       else:
           assert "Un-supported interface"
       endif

       if valueReadingType == "reading":
           valueReadingType = "IPMI_TYPE_READING"
       elif valueReadingType == "assertion":
           valueReadingType = "IPMI_TYPE_ASSERTION"
       else:
           assert "Unknown reading type"
       endif

       getValFunc = "std::bind(getValue," + str(byteOffset) + ", std::placeholders::_1)"

%>
        ${sensorType},"${path}",${readingType},${multiplier},${offset},${exp},
        ${offset * pow(10,exp)},"${updateInterface}",
        ${valueReadingType},${updateFunc},${getValFunc},{
    % for interface,properties in interfaces.iteritems():
            {"${interface}",{
            % for dbus_property,property_value in properties.iteritems():
                {"${dbus_property}",{
                % for offset,values in property_value.iteritems():
                    { ${offset},{
                        <% valueType = values["type"] %>\
                     % for name,value in values.iteritems():
                        % if name == "type":
                             <% continue %>\
                        % endif
                        % if valueType == "string":
                           std::string("${value}"),
                        % elif valueType == "bool":
                           <% value = str(value).lower() %>\
                           ${value},
                        % else:
                           ${value},
                        % endif
                     % endfor
                        }
                    },
                % endfor
                }},
            % endfor
            }},
    % endfor
     }
}},
   % endif
% endfor
};


