## This file is a template.  The comment below is emitted
## into the rendered file; feel free to edit this file.

// !!! WARNING: This is a GENERATED Code..Please do NOT Edit !!!
<%
from collections import defaultdict
readingTypes = { 'reading': 'cmdData->reading',
                 'assertion': '0',
                 'eventdata1': 'cmdData->eventData1',
                 'eventdata2': 'cmdData->eventData2',
                 'eventdata3': 'cmdData->eventData3'}
funcProps = {}
%>\
%for key in sensorDict.iterkeys():
<%
    sensor = sensorDict[key]
    command = ""
    updateFunc = ""
    sensorType = str(sensor["sensorType"])
    serviceInterface = sensor["serviceInterface"]
    readingType = sensor["readingType"]
    if serviceInterface == "org.freedesktop.DBus.Properties":
        command = "Set"
    elif serviceInterface == "xyz.openbmc_project.Inventory.Manager":
        command = "Notify"
    else:
        assert "Un-supported interface: serviceInterface"
    endif
    updateFunc = "sensor_set::sensortype" + sensorType + "::update"
    funcProps[sensorType] = {}
    funcProps[sensorType].update({"command" : command})
    funcProps[sensorType].update({"path" : sensor["path"]})
    funcProps[sensorType].update({"serviceInterface" : serviceInterface})
    funcProps[sensorType].update({"updateFunc" : updateFunc})
    funcProps[sensorType].update({"readingType" : readingType})
    funcProps[sensorType].update({"source" : readingTypes[readingType]})
    funcProps[sensorType].update({"interfaces" : sensor["interfaces"]})
%>\
% endfor
#include <bitset>
#include "types.hpp"
#include "host-ipmid/ipmid-api.h"
#include <phosphor-logging/elog-errors.hpp>
#include "xyz/openbmc_project/Common/error.hpp"
#include <phosphor-logging/log.hpp>
#include "sensordatahandler.hpp"

namespace ipmi
{
namespace sensor
{


namespace sensor_set
{
% for sensorType, funcProp in funcProps.iteritems():
namespace sensortype${sensorType}
{

ipmi_ret_t update(SetSensorReadingReq* cmdData,
                  Info sensorInfo)
{
    auto msg = ${funcProp["command"]}::makeDbusMsg(
                    "${funcProp['serviceInterface']}",
                    "${funcProp['path']}",
                    "${funcProp['command']}");

    auto interfaceList = sensorInfo.sensorInterfaces;
% for interface, properties in funcProp["interfaces"].iteritems():
    % for dbus_property, property_value in properties.iteritems():
        % for offset, values in property_value.iteritems():
            % if offset == 0xFF:
<%                funcName = "sendData"%>\
<%                param = "static_cast<"+values["type"]+">("+funcProp["source"]+")"%>\
            %  elif funcProp["readingType"] == "assertion":
<%                funcName = "assertion"%>\
<%                param = '"'+funcProp['path']+'", cmdData'%>\
            % else:
<%                funcName = "discreteSignal"%>\
<%                param = funcProp["source"]%>\
            % endif
        % endfor
    % endfor
% endfor
    auto l_ret = ${funcProp["command"]}::${funcName}(msg,
                        interfaceList,
                        ${param});
    if (l_ret != IPMI_CC_OK)
    {
        return l_ret;
    }
    return updateToDbus(msg); 
}
}//namespace sensortype${sensorType}

% endfor
}//namespace sensor_get
}//namespace sensor
}//namespace ipmi

using namespace ipmi::sensor;
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
       updateFunc = funcProps[str(sensorType)]["updateFunc"]
%>
        ${sensorType},"${path}",${readingType},${multiplier},${offset},${exp},
        ${offset * pow(10,exp)},${updateFunc},{
    % for interface,properties in interfaces.iteritems():
            {"${interface}",{
            % for dbus_property,property_value in properties.iteritems():
                {"${dbus_property}",{
                % for offset,values in property_value.iteritems():
                    { ${offset},{
                        % if offset == 0xFF:
                            }},
<%                          continue %>\
                        % endif
<%                          valueType = values["type"] %>\
                    % for name,value in values.iteritems():
                        % if name == "type":
<%                          continue %>\
                        % endif
                        % if valueType == "string":
                           std::string("${value}"),
                        % elif valueType == "bool":
<%                         value = str(value).lower() %>\
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

