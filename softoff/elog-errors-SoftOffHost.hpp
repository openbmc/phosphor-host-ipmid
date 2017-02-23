#pragma once

#include <map>
#include <string>
#include <tuple>
#include <type_traits>
#include <vector>
#include <phosphor-logging/log.hpp>

// !! UNTIL LOGGING CHANGES ARE MERGED. THIS IS TO GET CI GOING !!
namespace phosphor
{
namespace logging
{

std::map<std::string,std::vector<std::string>> g_errMetaMapHostSoftOff = {
     {"xyz.openbmc_project.Error.SoftOff.HOST.HOST",{"SHUTDOWN_TIMED_OUT"}},
};

std::map<std::string,level> g_errLevelMapHostSoftOff = {
     {"xyz.openbmc_project.Error.SoftOff.HOST.HOST",level::INFO},
};

namespace xyz
{
namespace openbmc_project
{
namespace Error
{
namespace SoftOff
{
namespace _HOST
{
struct SHUTDOWN_TIMED_OUT
{
    static constexpr auto str = "SHUTDOWN_TIMED_OUT=%llu";
    static constexpr auto str_short = "SHUTDOWN_TIMED_OUT";
    using type = std::tuple<std::decay_t<decltype(str)>,const char*>;
    explicit constexpr SHUTDOWN_TIMED_OUT(const char* a) : _entry(entry(str, a)) {};
    type _entry;
};

}  // namespace _HOST

struct HOST
{
    static constexpr auto err_code = "xyz.openbmc_project.Error.SoftOff.HOST.HOST";
    static constexpr auto err_msg = "Host did not shutdown within configured time";
    static constexpr auto L = level::INFO;
    using SHUTDOWN_TIMED_OUT = _HOST::SHUTDOWN_TIMED_OUT;
    using metadata_types = std::tuple<SHUTDOWN_TIMED_OUT>;
};
} // namespace SoftOff
} // namespace Error
} // namespace openbmc_project
} // namespace xyz
} // namespace logging
} // namespace phosphor
