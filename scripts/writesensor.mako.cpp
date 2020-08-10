## This file is a template.  The comment below is emitted
## into the rendered file; feel free to edit this file.
// !!! WARNING: This is a GENERATED Code..Please do NOT Edit !!!
<%
interfaceDict = {}
sensorNameMaxLength = 16
%>\
%for key in sensorDict.keys():
<%
    sensor = sensorDict[key]
    serviceInterface = sensor["serviceInterface"]
    if serviceInterface == "org.freedesktop.DBus.Properties":
        updateFunc = "set::"
        getFunc = "get::"
    elif serviceInterface == "xyz.openbmc_project.Inventory.Manager":
        updateFunc = "notify::"
        getFunc = "inventory::get::"
    else:
        assert "Un-supported interface: " + serviceInterface
    endif
    if serviceInterface not in interfaceDict:
        interfaceDict[serviceInterface] = {}
        interfaceDict[serviceInterface]["updateFunc"] = updateFunc
        interfaceDict[serviceInterface]["getFunc"] = getFunc
%>\
% endfor

#include "sensordatahandler.hpp"

#include <ipmid/types.hpp>

namespace ipmi {
namespace sensor {

extern const IdInfoMap sensors = {
% for key in sensorDict.keys():
   % if key:
{${key},{
<%
       sensor = sensorDict[key]
       interfaces = sensor["interfaces"]
       path = sensor["path"]
       serviceInterface = sensor["serviceInterface"]
       sensorType = sensor["sensorType"]
       entityID = sensor.get("entityID", 0)
       instance = sensor.get("entityInstance", 0)
       readingType = sensor["sensorReadingType"]
       multiplier = sensor.get("multiplierM", 1)
       offsetB = sensor.get("offsetB", 0)
       bExp = sensor.get("bExp", 0)
       rExp = sensor.get("rExp", 0)
       unit = sensor.get("unit", "")
       scale = sensor.get("scale", 0)
       hasScale = "true" if "scale" in sensor.keys() else "false"
       valueReadingType = sensor["readingType"]
       updateFunc = interfaceDict[serviceInterface]["updateFunc"]
       updateFunc += sensor["readingType"]
       getFunc = interfaceDict[serviceInterface]["getFunc"]
       getFunc += sensor["readingType"]
       sensorName = sensor.get("sensorName", None)
       if sensorName:
           assert len(sensorName) <= sensorNameMaxLength, \
                   "sensor name '%s' is too long (%d bytes max)" % \
                   (sensorName, sensorNameMaxLength)
       else:
           sensorNameFunc = "get::" + sensor.get("sensorNamePattern",
                   "nameLeaf")

       if "readingAssertion" == valueReadingType or "readingData" == valueReadingType:
           for interface,properties in interfaces.items():
               for dbus_property,property_value in properties.items():
                   for offset,values in property_value["Offsets"].items():
                       valueType = values["type"]
           updateFunc = "set::" + valueReadingType + "<" + valueType + ">"
           getFunc = "get::" + valueReadingType + "<" + valueType + ">"
       sensorInterface = serviceInterface
       if serviceInterface == "org.freedesktop.DBus.Properties":
           sensorInterface = next(iter(interfaces))
       mutability = sensor.get("mutability", "Mutability::Read")
%>
        .entityType = ${entityID},
        .instance = ${instance},
        .sensorType = ${sensorType},
        .sensorPath = "${path}",
        .sensorInterface = "${sensorInterface}",
        .sensorReadingType = ${readingType},
        .coefficientM = ${multiplier},
        .coefficientB = ${offsetB},
        .exponentB = ${bExp},
        .scaledOffset = ${offsetB * pow(10,bExp)},
        .exponentR = ${rExp},
        .hasScale = ${hasScale},
        .scale = ${scale},
        .unit = "${unit}",
        .updateFunc = ${updateFunc},
        .getFunc = ${getFunc},
        .mutability = Mutability(${mutability}),
    % if sensorName:
        .sensorName = "${sensorName}",
    % else:
        .sensorNameFunc = ${sensorNameFunc},
    % endif
        .propertyInterfaces = {
    % for interface,properties in interfaces.items():
            {"${interface}",{
            % if properties:
                % for dbus_property,property_value in properties.items():
                    {"${dbus_property}",{
<%
try:
    preReq = property_value["Prereqs"]
except KeyError:
    preReq = dict()
%>\
                    {
                        % for preOffset,preValues in preReq.items():
                        { ${preOffset},{
                            % for name,value in preValues.items():
                                % if name == "type":
<%                              continue %>\
                                % endif
<%                          value = str(value).lower() %>\
                                ${value},
                            % endfor
                            }
                        },
                        % endfor
                    },
                    {
                    % for offset,values in property_value["Offsets"].items():
                        { ${offset},{
                            % if offset == 0xFF:
                                }},
<%                          continue %>\
                            % endif
<%                          valueType = values["type"] %>\
<%
try:
    skip = values["skipOn"]
    if skip == "assert":
        skipVal = "SkipAssertion::ASSERT"
    elif skip == "deassert":
        skipVal = "SkipAssertion::DEASSERT"
    else:
        assert "Unknown skip value " + str(skip)
except KeyError:
    skipVal = "SkipAssertion::NONE"
%>\
                                ${skipVal},
                        % for name,value in values.items():
                            % if name == "type" or name == "skipOn":
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
                    }}},
                % endfor
            % endif
            }},
    % endfor
     },
}},
   % endif
% endfor
};

} // namespace sensor
} // namespace ipmi
