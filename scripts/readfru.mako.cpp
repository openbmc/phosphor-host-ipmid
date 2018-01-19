// !!! WARNING: This is a GENERATED Code..Please do NOT Edit !!!
#include <iostream>
#include "fruread.hpp"

const FruMap frus = {
% for key in fruDict.keys():
   {${key},{
<%
    fru = fruDict[key]
%>
    % for object,interfaces in fru.items():
         {"${object}",{
         % for interface,properties in interfaces.items():
             {"${interface}",{
            % if properties:
                % for dbus_property,property_value in properties.items():
                    {"${dbus_property}",{
                        "${property_value.get("IPMIFruSection", "")}",
                        "${property_value.get("IPMIFruProperty", "")}", \
<%
    delimiter = property_value.get("IPMIFruValueDelimiter")
    if not delimiter:
        delimiter = ""
    else:
        delimiter = '\\' + hex(delimiter)[1:]
%>
                     "${delimiter}"
                 }},
                % endfor
            %endif
             }},
         % endfor
        }},
    % endfor
   }},
% endfor
};
