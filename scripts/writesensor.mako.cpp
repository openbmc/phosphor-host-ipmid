## This file is a template.  The comment below is emitted
## into the rendered file; feel free to edit this file.

// !!! WARNING: This is a GENERATED Code..Please do NOT Edit !!!
<%
from collections import defaultdict
funcProps = defaultdict(tuple)
%>\
%for key in sensorDict.iterkeys():
<%
    sens = sensorDict[key]
    command = ""
    updateFunc = ""
    if sens["updateInterface"] == "org.freedesktop.DBus.Properties":
        updateFunc = "setPropertySensorReading"
        command = "Set"
    elif sens["updateInterface"] == "xyz.openbmc_project.Inventory.Manager":
        updateFunc = "setInventorySensorReading"
        command = "Notify"
    else:
        assert "Un-supported interface"
    endif
    funcProps[updateFunc] = (command, sens["updateInterface"])
%>\
% endfor
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
using DbusInfo = std::pair<std::string, std::string>;

DbusInfo getDbusInfo(sdbusplus::bus::bus& bus, std::string interface)
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

    return std::make_pair(mapperResponse.begin()->first,
        mapperResponse.begin()->second.begin()->first);
}

uint8_t getValue(ValueReadingType readingType, SetSensorReadingReq *cmd)
{
    if (readingType == IPMI_TYPE_ASSERTION)
    {
        return 0;
    }
    if(readingType == IPMI_TYPE_EVENT1)
    {
        return cmd->eventData1;
    }
    if(readingType == IPMI_TYPE_EVENT2)
    {
        return cmd->eventData2;
    }
    if (readingType == IPMI_TYPE_EVENT3)
    {
        return cmd->eventData3;
    }
    if (readingType == IPMI_TYPE_READING)
    {
        return cmd->reading;
    }
    return 0;
}

using Assertion = uint16_t;
using Deassertion = uint16_t;
using AssertionSet = std::pair<Assertion, Deassertion>;

AssertionSet getAssertionSet(SetSensorReadingReq *cmdData)
{

    Assertion assertionStates =
            (static_cast<Assertion>(cmdData->assertOffset8_14)) << 8 |
            cmdData->assertOffset0_7;
    Deassertion deassertionStates =
            (static_cast<Deassertion>(cmdData->deassertOffset8_14)) << 8 |
            cmdData->deassertOffset0_7;
    return std::make_pair(assertionStates,deassertionStates);
}

% for funcName, funcProp in funcProps.iteritems():
uint8_t ${funcName}(SetSensorReadingReq *cmdData,
                                 Info sensorInfo)
{
    std::bitset<16> assertionSet(getAssertionSet(cmdData).first);
    std::bitset<16> deassertionSet(getAssertionSet(cmdData).second);

% if funcProp[0] == "Set":
    uint8_t setVal = sensorInfo.getSensorValue(cmdData);
    auto& rtype = sensorInfo.valueReadingType;
% endif

    auto& interfaceList = sensorInfo.sensorInterfaces;
    if (interfaceList.empty())
    {
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    using namespace std::string_literals;
    DbusInfo service;

% if funcProp[0] == "Notify":
    std::string intf = "${funcProp[1]}"s;
% else:
    auto& intf = interfaceList.begin()->first;
% endif
    try
    {
        service = getDbusInfo(bus, "${funcProp[1]}");
    }
    catch (const std::runtime_error& e)
    {
        log<level::ERR>(e.what());
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    auto updMsg = bus.new_method_call(service.second.c_str(),
                                      service.first.c_str(),
                                      intf.c_str(),
                                     "${funcProp[0]}");
% if funcProp[0] == "Set":
    //for each interface in the list
    for (const auto& interface : interfaceList)
    {

        updMsg.append(interface.first);

        for (const auto& property : interface.second)
        {
            updMsg.append(property.first);

            if (rtype == IPMI_TYPE_READING)
            {
                updMsg.append(setVal);
                break;
            }
            for (const auto& value : property.second)
            {
                //for assertion type check whether bit is set.
                if (rtype == IPMI_TYPE_ASSERTION)
                {
                    if (assertionSet.test(value.first))
                    {
                        updMsg.append(value.second.assert);
                    }
                    if (deassertionSet.test(value.first))
                    {
                        updMsg.append(value.second.deassert);
                    }
                }
                else if (setVal == value.first)
                {
                        updMsg.append(value.second.assert);
                }
            }
        }
    }
%else:
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
    updMsg.append(std::move(objects));
% endif

    try
    {
        auto serviceResponseMsg = bus.call(updMsg);
        if (serviceResponseMsg.is_method_error())
        {
            log<level::ERR>("Error in set call");
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
% endfor

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
       elif valueReadingType == "event1":
           valueReadingType = "IPMI_TYPE_EVENT1"
       elif valueReadingType == "event2":
           valueReadingType = "IPMI_TYPE_EVENT2"
       elif valueReadingType == "event3":
           valueReadingType = "IPMI_TYPE_EVENT3"
       else:
           assert "Unknown reading type"
       endif

       getValFunc = "std::bind(getValue, "+ valueReadingType +", std::placeholders::_1)"

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


