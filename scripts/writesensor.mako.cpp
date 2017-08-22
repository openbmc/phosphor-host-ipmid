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
    elif serviceInterface == "xyz.openbmc_project.Inventory.Manager":
        updateFunc = "notify::"
    else:
        assert "Un-supported interface: " + serviceInterface
    endif
    if serviceInterface not in interfaceDict:
        interfaceDict[serviceInterface] = {}
        interfaceDict[serviceInterface]["updateFunc"] = updateFunc
%>\
% endfor

#include "types.hpp"
#include "sensordatahandler.hpp"

using namespace ipmi::sensor;

%for key in sensorDict.iterkeys():
<%
    sensor = sensorDict[key]
    readingType = sensor["readingType"]
    interfaces = sensor["interfaces"]
    for interface, properties in interfaces.items():
        for property, values in properties.items():
            for offset, attributes in values.items():
                type = attributes["type"]
%>\
%if "readingAssertion" == readingType:
namespace sensor_${key}
{

inline ipmi_ret_t readingAssertion(const SetSensorReadingReq& cmdData,
                                   const Info& sensorInfo)
{
    return set::readingAssertion<${type}>(cmdData, sensorInfo);
}

} // namespace sensor_${key}

%endif
% endfor

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
       offset = sensor.get("offsetB", 0)
       exp = sensor.get("bExp", 0)
       valueReadingType = sensor["readingType"]
       updateFunc = interfaceDict[serviceInterface]["updateFunc"]
       updateFunc += sensor["readingType"]
       if "readingAssertion" == valueReadingType:
           updateFunc = "sensor_" + str(key) + "::" + valueReadingType
       sensorInterface = serviceInterface
       if serviceInterface == "org.freedesktop.DBus.Properties":
           sensorInterface = next(iter(interfaces))
%>
        ${sensorType},"${path}","${sensorInterface}",${readingType},${multiplier},
        ${offset},${exp},${offset * pow(10,exp)},${updateFunc},{
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
<%                      valueType = values["type"] %>\
<%                      
try:
    skip = values["skipOn"]
    if skip == "false":
         skipVal = "FALSE"
    elif skip == "true":
         skipVal = "TRUE"
    else:
         assert "Unknown skip value " + str(skip)
except KeyError, e:
    skipVal = "NONE"
%>
                            ${skipVal},
                    % for name,value in values.items():
                        % if name == "type" or name == "skipOn":
<%                          continue %>\
                        % endif
                        % if name == "skipOn":
                            std::string("${value}"),
                        % elif valueType == "string":
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

