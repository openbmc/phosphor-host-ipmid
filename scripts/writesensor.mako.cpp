## This file is a template.  The comment below is emitted
## into the rendered file; feel free to edit this file.

// !!! WARNING: This is a GENERATED Code..Please do NOT Edit !!!

#include "types.hpp"
using namespace ipmi::sensor;

extern const IDInfoMap sensors = {
% for key in sensorDict.iterkeys():
   % if key:
{${key},{
<%
       sensor = sensorDict[key]
       interfaces = sensor["interfaces"]
       path = sensor["path"]
       sensorType = sensor["sensorType"]
       readingType = sensor["sensorReadingType"]
%>
        ${sensorType},"${path}",${readingType},{
    % for interface,properties in interfaces.iteritems():
            {"${interface}",{
            % for dbus_property,property_value in properties.iteritems():
                {"${dbus_property}",{
                % for offset,values in property_value.iteritems():
                    { ${offset},{
                    <% valueType = values["type"] %>
                     % for name,value in values.iteritems():
                        % if name == "type":
                           <% continue %>
                        % endif

                        % if valueType == "string":
                           std::move(std::string("${value}")),
                        % else:
                           ${value},
                        % endif
                     % endfor
                        }
                    },
                % endfor
                }},
            % endfor
            }},}
    % endfor
     }
},
   % endif
% endfor
};

