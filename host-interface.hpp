#pragma once

#include <sdbusplus/bus.hpp>
#include <xyz/openbmc_project/Control/Host/server.hpp>
#include <host-cmd-manager.hpp>
namespace phosphor
{
namespace host
{
namespace command
{

// IPMI OEM command
using OEMCmd = uint8_t;

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
         *  @param[in] bus     - The Dbus bus object
         *  @param[in] objPath - The Dbus object path
         */
        Host(sdbusplus::bus::bus& bus,
             const char* objPath) :
             sdbusplus::server::object::object<
                sdbusplus::xyz::openbmc_project::Control::server::Host>(
                        bus, objPath),
             bus(bus)
        {
            // Nothing to do
        }

        /** @brief Send input command to host
         *         Note that the command will be queued in a FIFO if
         *         other commands to the host have yet to be run
         *
         *  @param[in] command - Input command to execute
         */
        void execute(Command command) override;

    private:
        /** @brief sdbusplus DBus bus connection. */
        sdbusplus::bus::bus& bus;

        /** @detail Map of IPMI OEM command TO its equivalent
         *          interface command. This is needed to send
         *          implementation specific Command execution
         *          status message. Could be Success or Failure
         */
        static const std::map<OEMCmd, Command> intfCommand;

        /** @detail Map of Interface command TO its corresponding
         *          IPMI OEM command. This is needed when pushing
         *          IPMI commands to command manager's queue. The
         *          same pair will be returned when IPMI asks us
         *          why a SMS_ATN was sent
         */
        static const std::map<Command, IpmiCmdData> ipmiCommand;

        /** @detail Callback function to be invoked by command manager
         *          conveying the status of the last Host bound command.
         *          Depending on the status,  a CommandComplete or
         *          CommandFailure signals would be sent
         *
         *  @param[in] cmd    - IPMI command and data sent to Host
         *  @param[in] status - Success or Failure
         *
         */
        void commandStatusHandler(IpmiCmdData cmd, bool status);
};

} // namespace command
} // namespace host
} // namespace phosphor
