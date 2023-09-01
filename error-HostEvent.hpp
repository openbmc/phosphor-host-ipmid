#pragma once

#include <sdbusplus/exception.hpp>

#include <cerrno>

namespace sdbusplus::error::org::open_power::host
{
struct Event final : public sdbusplus::exception::generated_exception
{
    static constexpr auto errName = "org.open_power.Host.Error.Event";
    static constexpr auto errDesc = "A host system event was received";
    static constexpr auto errWhat =
        "org.open_power.Host.Error.Event: A host system event was received";

    const char* name() const noexcept override
    {
        return errName;
    }
    const char* description() const noexcept override
    {
        return errDesc;
    }
    const char* what() const noexcept override
    {
        return errWhat;
    }
};
struct MaintenanceProcedure final :
    public sdbusplus::exception::generated_exception
{
    static constexpr auto errName =
        "org.open_power.Host.Error.MaintenanceProcedure";
    static constexpr auto errDesc =
        "A host system event with a procedure callout";
    static constexpr auto errWhat =
        "org.open_power.Host.Error.MaintenanceProcedure: A host system event with a procedure callout";

    const char* name() const noexcept override
    {
        return errName;
    }
    const char* description() const noexcept override
    {
        return errDesc;
    }
    const char* what() const noexcept override
    {
        return errWhat;
    }
};
} // namespace sdbusplus::error::org::open_power::host

#ifndef SDBUSPP_REMOVE_DEPRECATED_NAMESPACE
namespace sdbusplus::org::open_power::Host::Error
{
using Event = sdbusplus::error::org::open_power::host::Event;
using MaintenanceProcedure =
    sdbusplus::error::org::open_power::host::MaintenanceProcedure;
} // namespace sdbusplus::org::open_power::Host::Error
#endif
