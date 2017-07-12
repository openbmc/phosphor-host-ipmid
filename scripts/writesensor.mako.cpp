## This file is a template.  The comment below is emitted
## into the rendered file; feel free to edit this file.

// !!! WARNING: This is a GENERATED Code..Please do NOT Edit !!!

#include "types.hpp"
#include "sensorhandlerex.hpp"
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
       updatePath = sensor["updatePath"]
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

       getValFunc = "std::bind(ipmi::sensor::getValue," + str(byteOffset) + ", std::placeholders::_1)"

%>
        ${sensorType},"${path}",${readingType},${multiplier},${offset},${exp},
        ${offset * pow(10,exp)},"${updatePath}","${updateInterface}",
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

