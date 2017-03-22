#pragma once

#include <queue>
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
                        bus, objPath),
             bus(bus)
        {}

        /** @brief Send input command to host
         *
         * Note that the command will be queued in a FIFO if other commands
         * to the host have yet to be run
         *
         * @param[in] command       - Input command to execute
         */
        void execute(Command command) override;

        /** @brief Return the next entry in the queue
         *
         *  Also signal that the command is complete since the interface
         *  contract is that we emit this signal once the message has been
         *  passed to the host (which is required when calling this interface)
         *
         */
        Command getNextCommand()
        {
            Command command = this->workQueue.front();
            this->workQueue.pop();
            this->commandComplete(command, Result::Success);
            return command;
        }

    private:

        /** @brief Persistent sdbusplus DBus bus connection. */
        sdbusplus::bus::bus& bus;

        /** @brief Queue to store the requested commands */
        std::queue<Command> workQueue{};
};

} // namespace host
} // namespace phosphor
