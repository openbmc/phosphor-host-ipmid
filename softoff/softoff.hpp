#pragma once

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/Ipmi/Internal/SoftPowerOff/server.hpp>
namespace phosphor
{
namespace ipmi
{

namespace Base = sdbusplus::xyz::openbmc_project::Ipmi::Internal::server;

/** @class SoftPowerOff
 *  @brief Responsible for coordinating Host SoftPowerOff operation
 */
class SoftPowerOff : public sdbusplus::server::object::object<
                     Base::SoftPowerOff>
{
    public:
        /** @brief Constructs SoftPowerOff object.
         *
         *  @param[in] bus       - system dbus handler
         *  @param[in] objPath   - The Dbus path that hosts SoftPowerOff function
         */
        SoftPowerOff(sdbusplus::bus::bus& bus,
                     const char* objPath) :
            sdbusplus::server::object::object<Base::SoftPowerOff>(bus, objPath)
        {
            // Nothing to do here
        }
};
} // namespace ipmi
} // namespace phosphor
