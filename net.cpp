#include <map>
#include <string>

// Not sure if this should live in utils.  Because it's really a per-system
// configuration, instead of just hard-coding channel 1 to be eth0, one could
// conceivably configure it however they pleased.
//
// In this design, channel 0 is the in-band host channel.

namespace ipmi
{
namespace network
{

// This map should come from a configuration yaml.
// Also, no need to really be a map, could be just an array
// we index into by channel. :D
std::map<int, std::string> ethDeviceMap = {
    {1, "eth0"},
    {2, "eth1"},
};


// Given a channel number, return a matching ethernet device, or empty string
// if there is no match.
// TODO provide this from a configuration:
// https://github.com/openbmc/openbmc/issues/2667
std::string ChanneltoEthernet(int channel)
{
    auto dev = ethDeviceMap.find(channel);
    if (dev == ethDeviceMap.end())
    {
        return "";
    }

    return dev->second;
}

} // namespace network
} // namespace ipmi

