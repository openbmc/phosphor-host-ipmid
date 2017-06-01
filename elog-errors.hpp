// This file was autogenerated.  Do not edit!
// See elog-gen.py for more details
#pragma once

#include <string>
#include <tuple>
#include <type_traits>
#include <sdbusplus/exception.hpp>
#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog.hpp>


namespace phosphor
{

namespace logging
{

namespace xyz
{
namespace openbmc_project
{
namespace Control
{
namespace Internal
{
namespace Host
{
namespace _QueueEmpty
{


}  // namespace _QueueEmpty

struct QueueEmpty : public sdbusplus::exception_t
{
    static constexpr auto errName = "xyz.openbmc_project.Control.Internal.Host.QueueEmpty";
    static constexpr auto errDesc = "The host response queue is empty and it should not be!";
    static constexpr auto L = level::ERR;
    using metadata_types = std::tuple<>;

    const char* name() const noexcept
    {
        return errName;
    }

    const char* description() const noexcept
    {
        return errDesc;
    }

    const char* what() const noexcept
    {
        return errName;
    }
};

} // namespace Host
} // namespace Internal
} // namespace Control
} // namespace openbmc_project
} // namespace xyz


namespace xyz
{
namespace openbmc_project
{
namespace Ipmi
{
namespace Internal
{
namespace Common
{
namespace _MkdirFailed
{
struct DIR
{
    static constexpr auto str = "DIR=%s";
    static constexpr auto str_short = "DIR";
    using type = std::tuple<std::decay_t<decltype(str)>,const char*>;
    explicit constexpr DIR(const char* a) : _entry(entry(str, a)) {};
    type _entry;
};
struct ERRNO
{
    static constexpr auto str = "ERRNO=%s";
    static constexpr auto str_short = "ERRNO";
    using type = std::tuple<std::decay_t<decltype(str)>,const char*>;
    explicit constexpr ERRNO(const char* a) : _entry(entry(str, a)) {};
    type _entry;
};

}  // namespace _MkdirFailed

struct MkdirFailed : public sdbusplus::exception_t
{
    static constexpr auto errName = "xyz.openbmc_project.Ipmi.Internal.Common.MkdirFailed";
    static constexpr auto errDesc = "An attempt to create a directory in the filesystem failed";
    static constexpr auto L = level::ERR;
    using DIR = _MkdirFailed::DIR;
    using ERRNO = _MkdirFailed::ERRNO;
    using metadata_types = std::tuple<DIR, ERRNO>;

    const char* name() const noexcept
    {
        return errName;
    }

    const char* description() const noexcept
    {
        return errDesc;
    }

    const char* what() const noexcept
    {
        return errName;
    }
};

} // namespace Common
} // namespace Internal
} // namespace Ipmi
} // namespace openbmc_project
} // namespace xyz


} // namespace logging

} // namespace phosphor
