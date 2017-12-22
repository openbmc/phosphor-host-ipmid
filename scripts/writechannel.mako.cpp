## This file is a template.  The comment below is emitted
## into the rendered file; feel free to edit this file.
// !!! WARNING: This is a GENERATED Code..Please do NOT Edit !!!

#include "types.hpp"

namespace ipmi
{
namespace network
{

extern const ChannelEthMap ethdevices = {
% for channel,channelInfo in interfaceDict.iteritems():
    {${channel},"${channelInfo['ifName']}"},
% endfor
};

} // namespace network
} // namespace ipmi

