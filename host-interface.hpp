#pragma once

#include <sdbusplus/bus.hpp>
#include <xyz/openbmc_project/Control/Host/server.hpp>

namespace phosphor
{
namespace host
{

/** @class Host
 *  @brief OpenBMC control host interface implementation.
 *  @details A concrete implementation for xyz.openbmc_project.Control.Host
 *  DBus API.
 */
class Host : public sdbusplus::server::object::object<
                sdbusplus::xyz::openbmc_project::Control::server::Host>
{
    public:
        /** @brief Constructs Host Control Interface
         *
         * @param[in] bus       - The Dbus bus object
         * @param[in] objPath   - The Dbus object path
         */
        Host(sdbusplus::bus::bus& bus,
             const char* objPath) :
             sdbusplus::server::object::object<
                sdbusplus::xyz::openbmc_project::Control::server::Host>(
                        bus, objPath)
        {}

        /** @brief Queue input command to be executed
         *
         * @param[in] command       - Input command to execute
         */
        void execute(Command command) override;
};

} // namespace host
} // namespace phosphor
