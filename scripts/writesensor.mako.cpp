## This file is a template.  The comment below is emitted
## into the rendered file; feel free to edit this file.

// !!! WARNING: This is a GENERATED Code..Please do NOT Edit !!!
<%
from collections import defaultdict
readingTypes = { 'reading': 'cmdData.reading',
                 'assertion': '((cmdData.assertOffset8_14 << 8)|cmdData.assertOffset0_7)',
                 'eventdata1': 'cmdData.eventData1',
                 'eventdata2': 'cmdData.eventData2',
                 'eventdata3': 'cmdData.eventData3'}
funcProps = {}
%>\
%for key in sensorDict.iterkeys():
<%
    sensor = sensorDict[key]
    sensorType = sensor["sensorType"]
    serviceInterface = sensor["serviceInterface"]
    readingType = sensor["readingType"]
    if serviceInterface == "org.freedesktop.DBus.Properties":
        command = "Set"
    elif serviceInterface == "xyz.openbmc_project.Inventory.Manager":
        command = "Notify"
    else:
        assert "Un-supported interface: serviceInterface"
    endif
    sensorInterface = serviceInterface
    for interface in sensor["interfaces"]:
       updateFunc = "sensor_set::interface_" + interface.replace('.','') + "::update"
       funcProps[interface] = {}
       funcProps[interface].update({"command" : command})
       funcProps[interface].update({"path" : sensor["path"]})
       funcProps[interface].update({"serviceInterface" : serviceInterface})
       funcProps[interface].update({"updateFunc" : updateFunc})
       funcProps[interface].update({"readingType" : readingType})
       funcProps[interface].update({"source" : readingTypes[readingType]})
       funcProps[interface].update({"interfaces" : sensor["interfaces"]})
       if command == "Set":
           for interface, props in funcProps[interface]["interfaces"].items():
               sensorInterface = interface
       funcProps[interface].update({"sensorInterface" : sensorInterface})
    endfor
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
% for interface, funcProp in funcProps.iteritems():
namespace interface_${interface.replace('.','')}
{

ipmi_ret_t update(const SetSensorReadingReq& cmdData,
                  const Info& sensorInfo)
{
    auto msg = ${(funcProp["command"]).lower()}::makeDbusMsg(
                    "${funcProp['serviceInterface']}",
                     sensorInfo.sensorPath,
                    "${funcProp['command']}",
                    "${funcProp['sensorInterface']}");

    auto interfaceList = sensorInfo.sensorInterfaces;
% for interface, properties in funcProp["interfaces"].iteritems():
    % for dbus_property, property_value in properties.iteritems():
        % for offset, values in property_value.iteritems():
            % if offset == 0xFF:
<%                funcName = "appendReadingData"%>\
<%                param = "static_cast<"+values["type"]+">("+funcProp["source"]+")"%>\
            %  elif funcProp["readingType"] == "assertion":
<%                funcName = "appendAssertion"%>\
<%                param = "sensorInfo.sensorPath, cmdData"%>\
            % else:
<%                funcName = "appendDiscreteSignalData"%>\
<%                param = funcProp["source"]%>\
            % endif
        % endfor
    % endfor
% endfor
    auto result = ${(funcProp["command"]).lower()}::${funcName}(msg,
                        "${interface}",
                        interfaceList.at("${interface}"),
                        ${param});
    if (result != IPMI_CC_OK)
    {
        return result;
    }
    return updateToDbus(msg);
}
}//namespace sensor_type_${sensorType}

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
%>\
<%
       updateFunc = funcProps[next(iter(interfaces))]["updateFunc"]
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

