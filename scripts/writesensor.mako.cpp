## This file is a template.  The comment below is emitted
## into the rendered file; feel free to edit this file.
// !!! WARNING: This is a GENERATED Code..Please do NOT Edit !!!
<%
interfaceDict = {}
%>\
%for key in sensorDict.iterkeys():
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

#include "types.hpp"
#include "sensordatahandler.hpp"

using namespace ipmi::sensor;

extern const IdInfoMap sensors = {
% for key in sensorDict.iterkeys():
   % if key:
{${key},{
<%
       sensor = sensorDict[key]
       interfaces = sensor["interfaces"]
       path = sensor["path"]
       serviceInterface = sensor["serviceInterface"]
       sensorType = sensor["sensorType"]
       readingType = sensor["sensorReadingType"]
       multiplier = sensor.get("multiplierM", 1)
       offsetB = sensor.get("offsetB", 0)
       exp = sensor.get("bExp", 0)
       valueReadingType = sensor["readingType"]
       updateFunc = interfaceDict[serviceInterface]["updateFunc"]
       updateFunc += sensor["readingType"]
       getFunc = interfaceDict[serviceInterface]["getFunc"]
       getFunc += sensor["readingType"]
       if "readingAssertion" == valueReadingType or "readingData" == valueReadingType:
           for interface,properties in interfaces.items():
               for dbus_property,property_value in properties.items():
                   for offset,values in property_value.items():
                       valueType = values["type"]
           updateFunc = "set::" + valueReadingType + "<" + valueType + ">"
           getFunc = "get::" + valueReadingType + "<" + valueType + ">"
       sensorInterface = serviceInterface
       if serviceInterface == "org.freedesktop.DBus.Properties":
           sensorInterface = next(iter(interfaces))
       mutability = sensor.get("mutability", "Mutability::Read")
%>
        ${sensorType},"${path}","${sensorInterface}",${readingType},${multiplier},
        ${offsetB},${exp},${offsetB * pow(10,exp)},${updateFunc},${getFunc},Mutability(${mutability}),{
    % for interface,properties in interfaces.items():
            {"${interface}",{
            % for dbus_property,property_value in properties.items():
                {"${dbus_property}",{
                % for offset,values in property_value.items():
                    { ${offset},{
                        % if offset == 0xFF:
                            }},
<%                          continue %>\
                        % endif
<%                          valueType = values["type"] %>\
                    % for name,value in values.items():
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
     },
}},
   % endif
% endfor
};

