## This file is a template.  The comment below is emitted
## into the rendered file; feel free to edit this file.

// !!! WARNING: This is a GENERATED Code..Please do NOT Edit !!!

#include "types.hpp"
using namespace ipmi::sensor;

extern const IdInfoMap sensors = {
% for key in sensorDict.iterkeys():
   % if key:
{ ${key},
<%
       sensor = sensorDict[key]
       interfaces = sensor["interfaces"]
       path = sensor["path"]
       sensorType = sensor["sensorType"]
       readingType = sensor["sensorReadingType"]
       updatePath = sensor["updatePath"]
       updateInterface = sensor["updateInterface"]
       command = sensor["command"]
%>
    { ${sensorType},"${path}",${readingType},"${updatePath}","${updateInterface}","${command}",{
        % for interface,bproperties in interfaces.iteritems():
        { "${interface}",{
            % for dbus_property,value_type in bproperties.iteritems():
            { "${dbus_property}",{
                % for value_type_name,value_contents in value_type.iteritems():
                { "${value_type_name}",{
                % for byteoffset, property_value in value_contents.iteritems():
                    { ${byteoffset},{
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
                             % elif valueType == "uint8":
                                    uint8_t(${value}),
                             % else:
                                    ${value}
                             % endif
                             % endfor
                        }},
                    % endfor
                    }},
                %endfor
                }},
            % endfor
            }},
        % endfor
        }},
    % endfor
    }},
},
% endif
% endfor
};

