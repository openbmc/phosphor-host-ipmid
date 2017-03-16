#pragma once

#include <sdbusplus/bus.hpp>
#include "xyz/openbmc_project/Host/server.hpp"

namespace phosphor
{
namespace host
{

/** @class Host
 *  @brief OpenBMC host interface implementation.
 *  @details A concrete implementation for xyz.openbmc_project.Host
 *  DBus API.
 */
class Host : public sdbusplus::server::object::object<
                sdbusplus::xyz::openbmc_project::server::Host>
{
    public:
        /** @brief Constructs Host Interface
         *
         * @param[in] bus       - The Dbus bus object
         * @param[in] busName   - The Dbus name to own
         * @param[in] objPath   - The Dbus object path
         */
        Host(sdbusplus::bus::bus& bus,
             const char* busName,
             const char* objPath) :
             sdbusplus::server::object::object<
                sdbusplus::xyz::openbmc_project::server::Host>(
                        bus, objPath)
        {}
};

} // namespace host
} // namespace phosphor
