#pragma once

#include <sdbusplus/exception.hpp>

namespace sdbusplus
{
namespace org
{
namespace open_power
{
namespace Host
{
namespace Event
{
namespace Error
{

struct Event final : public sdbusplus::exception_t
{
    static constexpr auto errName = "org.open_power.Host.Event.Error.Event";
    static constexpr auto errDesc =
            "A host system event was received";
    static constexpr auto errWhat =
            "org.open_power.Host.Event.Error.Event: A host system event was received";

    const char* name() const noexcept override;
    const char* description() const noexcept override;
    const char* what() const noexcept override;
};

} // namespace Error
} // namespace Event
} // namespace Host
} // namespace open_power
} // namespace org
} // namespace sdbusplus

