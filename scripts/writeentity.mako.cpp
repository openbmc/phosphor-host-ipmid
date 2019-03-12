## This file is a template.  The comment below is emitted
## into the rendered file; feel free to edit this file.
// !!! WARNING: This is a GENERATED Code..Please do NOT Edit !!!

#include <ipmid/types.hpp>
using namespace ipmi::sensor;

extern const EntityInfoMap entities = {
% for key in entityDict.iterkeys():
{${key},{
<%
       entity = entityDict[key]
       containerEntityId = entity["containerEntityId"]
       containerEntityInstance = entity["containerEntityInstance"]
       isList = entity["isList"]
       isLinked = entity["isLinked"]
       entityId1 = entity["entityId1"]
       entityInstance1 = entity["entityInstance1"]
       entityId2 = entity["entityId2"]
       entityInstance2 = entity["entityInstance2"]
       entityId3 = entity["entityId3"]
       entityInstance3 = entity["entityInstance3"]
       entityId4 = entity["entityId4"]
       entityInstance4 = entity["entityInstance4"]
%>
        ${containerEntityId},${containerEntityInstance},${isList},${isLinked},{
          std::make_pair(${entityId1}, ${entityInstance1}),
          std::make_pair(${entityId2}, ${entityInstance2}),
          std::make_pair(${entityId3}, ${entityInstance3}),
          std::make_pair(${entityId4}, ${entityInstance4}) }

}},
% endfor
};
