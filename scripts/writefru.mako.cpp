// !!! WARNING: This is a GENERATED Code..Please do NOT Edit !!!
#include <iostream>
#include "frup.hpp"

extern const FruMap frus = {
% for key in fruDict.iterkeys():
   {${key},{
<%
    fru = fruDict[key]
%>
    % for object,interfaces in fru.iteritems():
         {"${object}",{
         % for interface,properties in interfaces.iteritems():
             {"${interface}",{
            % for dbus_property,property_value in properties.iteritems():
                 {"${dbus_property}",{
                % for name,value in property_value.iteritems():
                     {"${name}","${value}"},
                % endfor
                 }},
            % endfor
             }},
         % endfor
        }},
    % endfor
   }},
% endfor
};
