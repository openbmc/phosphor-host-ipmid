#include "utils.hpp"

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

extern const ipmi::network::ChannelEthMap ethdevices;

// Given a channel number, return a matching ethernet device, or empty string
// if there is no match.
std::string ChanneltoEthernet(int channel)
{
    auto dev = ethdevices.find(channel);
    if (dev == ethdevices.end())
    {
        return "";
    }

    return dev->second;
}

} // namespace network
} // namespace ipmi
