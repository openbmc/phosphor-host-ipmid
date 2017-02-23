## This file is a template.  The comment below is emitted
## into the rendered file; feel free to edit this file.

// !!! WARNING: This is a GENERATED Code..Please do NOT Edit !!!

#include "types.hpp"

extern const sensorMap sensors = {
% for key in sensorDict.iterkeys():
   % if key:
{${key},{
<%
       sensor = sensorDict[key]
       interfaces = sensor["interfaces"]
       path = sensor["path"]
       type = sensor["sensorType"]
       readingType = sensor["sensorReadingType"]
%>
        ${type},"${path}",${readingType},{
    % for interface,properties in interfaces.iteritems():
            {"${interface}",{
            % for dbus_property,property_value in properties.iteritems():
                {"${dbus_property}",{
                % for name,value in property_value.iteritems():
                    {"${name}","${value}"},
                % endfor
                }},
            % endfor
            }},}
    % endfor
     }
},
   %endif
% endfor
};

