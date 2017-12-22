## This file is a template.  The comment below is emitted
## into the rendered file; feel free to edit this file.
// !!! WARNING: This is a GENERATED Code..Please do NOT Edit !!!

#include "types.hpp"

using namespace ipmi::network;

extern const ChannelEthMap ethdevices = {
% for key in sensorDict.iterkeys():
    {${key},"${sensorDict[key]['ifName']}"},
% endfor
};
