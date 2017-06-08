#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <vector>

#include "host-ipmid/ipmid-api.h"

namespace ipmid
{

using Byte = uint8_t;
constexpr size_t oemGroupMagicSize = 3;
using OemGroup = std::array<Byte, oemGroupMagicSize>;
using OemNumber = uint32_t;  // smallest standard size >= 24.

// Handler signature includes ipmi cmd to support wildcard cmd match.
// Buffers and lengths exclude the OemGroup bytes in the IPMI message.
// dataLen supplies length of reqBuf upon call, and should be set to the
// length of replyBuf upon return - conventional in this code base.
using OemHandler = std::function<ipmi_ret_t(
                       ipmi_cmd_t,   // cmd byte
                       const Byte*,  // reqBuf
                       Byte*,        // replyBuf
                       size_t*)>;    // dataLen

// OemRouter Interface class.
class OemRouter
{
    public:
        virtual ~OemRouter() {}

        // Enable message routing to begin.
        virtual void activate() = 0;

        // Register a handler for given OEMNumber & cmd.
        // Use IPMI_CMD_WILDCARD to catch any unregistered cmd
        // for the given OEMNumber.
        virtual void registerHandler(OemNumber oen, ipmi_cmd_t cmd,
                                     OemHandler handler) = 0;
};

// Expose mutable OemRouter for configuration & activation.
OemRouter* mutableOemRouter();

// OemGroup helpers.
constexpr OemNumber toOemNumber(const Byte oeg[oemGroupMagicSize])
{
    return (oeg[2] << 16) | (oeg[1] << 8) | oeg[0];
}

constexpr OemNumber toOemNumber(const OemGroup& oeg)
{
    return (oeg[2] << 16) | (oeg[1] << 8) | oeg[0];
}

constexpr OemGroup toOemGroup(OemNumber oen)
{
    return OemGroup { static_cast<Byte>(oen),
                      static_cast<Byte>(oen >> 8),
                      static_cast<Byte>(oen >> 16) };
}

}  // namespace ipmid
