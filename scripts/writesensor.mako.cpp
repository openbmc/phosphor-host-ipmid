## This file is a template.  The comment below is emitted
## into the rendered file; feel free to edit this file.

// !!! WARNING: This is a GENERATED Code..Please do NOT Edit !!!
<%
from collections import defaultdict
funcProps = defaultdict(tuple)
%>\
%for key in sensorDict.iterkeys():
<%
    sensor = sensorDict[key]
    command = ""
    updateFunc = ""
    if sensor["serviceInterface"] == "org.freedesktop.DBus.Properties":
        command = "Set"
        
    elif sensor["serviceInterface"] == "xyz.openbmc_project.Inventory.Manager":
        command = "Notify"
    else:
        assert "Un-supported interface: sensor[serviceInterface]"
    endif
    updateFunc = "sensor_set::"+command + "::update"
    funcProps[sensor["serviceInterface"]] = (command, sensor["serviceInterface"])
%>\
% endfor
#include <bitset>
#include "types.hpp"
#include "host-ipmid/ipmid-api.h"
#include <phosphor-logging/elog-errors.hpp>
#include "xyz/openbmc_project/Common/error.hpp"
#include <phosphor-logging/log.hpp>

namespace ipmi
{
namespace sensor
{

using namespace phosphor::logging;
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
 
constexpr auto MAPPER_BUSNAME = "xyz.openbmc_project.ObjectMapper";
constexpr auto MAPPER_PATH = "/xyz/openbmc_project/object_mapper";
constexpr auto MAPPER_INTERFACE = "xyz.openbmc_project.ObjectMapper";

using namespace phosphor::logging;

using Service = std::string;
using Path = std::string;
using Interface = std::string;

using DbusInfo = std::pair<Path, Service>;

using Interfaces = std::vector<Interface>;

using MapperResponseType = std::map<Path,
                           std::map<Service, Interfaces>>;

/** @brief get the D-Bus service and service path
 *  @param in bus
 *  @param in interface to the service
 *  @return pair of service path and service
 */
DbusInfo getDbusInfo(sdbusplus::bus::bus& bus, const std::string& interface)
{
    auto depth = 0;
    auto mapperCall = bus.new_method_call(MAPPER_BUSNAME,
                                          MAPPER_PATH,
                                          MAPPER_INTERFACE,
                                          "GetSubTree");
    mapperCall.append("/");
    mapperCall.append(depth);
    mapperCall.append(std::vector<Interface>({interface}));


    auto mapperResponseMsg = bus.call(mapperCall);
    if (mapperResponseMsg.is_method_error())
    {
        log<level::ERR>("Error in mapper GetSubTree");
        elog<InternalFailure>();
    }

    MapperResponseType mapperResponse;
    mapperResponseMsg.read(mapperResponse);
    if (mapperResponse.empty())
    {
        log<level::ERR>("Invalid response from mapper");
        elog<InternalFailure>();
    }

    return std::make_pair(mapperResponse.begin()->first,
        mapperResponse.begin()->second.begin()->first);
}

using SensorValue = uint8_t;

/** @brief get the value from the command struct
 *  @param in type of sensor reading
 *  @param in pointer to the command struct
 *  @return value based on sensor reading type
 */
SensorValue getValue(ValueReadingType readingType, SetSensorReadingReq *cmd)
{
    switch(readingType)
    {
        case IPMI_TYPE_ASSERTION:
            return 0;
        case IPMI_TYPE_EVENT1:
            return cmd->eventData1;
        case IPMI_TYPE_EVENT2:
            return cmd->eventData2;
        case IPMI_TYPE_EVENT3:
            return cmd->eventData3;
        case IPMI_TYPE_READING:
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
    return std::make_pair(assertionStates, deassertionStates);
}

namespace sensor_set
{
% for interface, funcProp in funcProps.iteritems():
namespace ${funcProp[0]}
{

ipmi_ret_t update(SetSensorReadingReq *cmdData,
                    Info sensorInfo)
{
    std::bitset<16> assertionSet(getAssertionSet(cmdData).first);
    std::bitset<16> deassertionSet(getAssertionSet(cmdData).second);

% if funcProp[0] == "Set":
    uint8_t setVal = sensorInfo.getSensorValue(cmdData);
    const auto& rtype = sensorInfo.valueReadingType;
% endif

    auto interfaceList = sensorInfo.sensorInterfaces;
    if (interfaceList.empty())
    {
        log<level::ERR>("No DBus interface list available with this sensor");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    using namespace std::string_literals;
    DbusInfo service;

% if funcProp[0] == "Notify":
    std::string intf = "${interface}"s;
% else:
    auto& intf = interfaceList.begin()->first;
% endif

    std::string dbusService;
    std::string dbusPath;

    try
    {
        std::tie(dbusService, dbusPath) = getDbusInfo(bus, "${interface}");
    }
    catch (InternalFailure& e)
    {
        commit<InternalFailure>();
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    auto updMsg = bus.new_method_call(dbusService.c_str(),
                                      dbusPath.c_str(),
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
            log<level::ERR>("Error in D-Bus call");
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
    }
    catch (InternalFailure& e)
    {
        commit<InternalFailure>();
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    return IPMI_CC_OK;
}

}//namespace ${funcProp[0]}
% endfor
}//namespace sensor_get
<% readingTypes = { 'reading':'IPMI_TYPE_READING',
                    'assertion': 'IPMI_TYPE_ASSERTION',
                    'eventdata1': 'IPMI_TYPE_EVENT1',
                    'eventdata2': 'IPMI_TYPE_EVENT2',
                    'eventdata3': 'IPMI_TYPE_EVENT3'}%> 
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
       valueReadingType = sensor["readingType"]
       updateFuc = funcProps[sensor["serviceInterface"]][1]
       valueReadingType = readingTypes[sensor["readingType"]]

       getValFunc = "std::bind(getValue, ipmi::sensor::"+ valueReadingType +", std::placeholders::_1)"

%>
        ${sensorType},"${path}",${readingType},${multiplier},${offset},${exp},
        ${offset * pow(10,exp)},${valueReadingType},${updateFunc},${getValFunc},{
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

}//namespace sensor
}//namespace ipmi
