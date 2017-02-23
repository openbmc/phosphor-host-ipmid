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
     {"xyz.openbmc_project.Error.SoftOff.Host.Host",{"SHUTDOWN_TIME_OUT"}},
};

std::map<std::string,level> g_errLevelMapHostSoftOff = {
     {"xyz.openbmc_project.Error.SoftOff.Host.Host",level::INFO},
};

namespace xyz
{
namespace openbmc_project
{
namespace Error
{
namespace SoftOff
{
namespace _Host
{
struct SHUTDOWN_TIME_OUT
{
    static constexpr auto str = "SHUTDOWN_TIME_OUT=%llu";
    static constexpr auto str_short = "SHUTDOWN_TIME_OUT";
    using type = std::tuple<std::decay_t<decltype(str)>,const char*>;
    explicit constexpr SHUTDOWN_TIME_OUT(const char* a) : _entry(entry(str, a)) {};
    type _entry;
};

}  // namespace _Host

struct Host
{
    static constexpr auto err_code = "xyz.openbmc_project.Error.SoftOff.Host.Host";
    static constexpr auto err_msg = "Host did not shutdown within configured time";
    static constexpr auto L = level::INFO;
    using SHUTDOWN_TIME_OUT = _Host::SHUTDOWN_TIME_OUT;
    using metadata_types = std::tuple<SHUTDOWN_TIME_OUT>;
};
} // namespace SoftOff
} // namespace Error
} // namespace openbmc_project
} // namespace xyz
} // namespace logging
} // namespace phosphor
