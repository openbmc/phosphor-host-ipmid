#pragma once

#include <host-cmd-manager.hpp>
#include <sdbusplus/bus.hpp>
#include <xyz/openbmc_project/Condition/HostFirmware/server.hpp>
#include <xyz/openbmc_project/Control/Host/server.hpp>
namespace phosphor
{
namespace host
{
namespace command
{

/** @class Host
 *  @brief OpenBMC control and condition host interface implementation.
 *  @details A concrete implementation for xyz.openbmc_project.Control.Host
 *  and xyz.openbmc_project.Condition.HostFirmware DBus API's.
 */
class Host
    : public sdbusplus::server::object_t<
          sdbusplus::xyz::openbmc_project::Control::server::Host,
          sdbusplus::xyz::openbmc_project::Condition::server::HostFirmware>
{
  public:
    /** @brief Constructs Host Control and Condition Interfaces
     *
     *  @param[in] bus     - The Dbus bus object
     *  @param[in] objPath - The Dbus object path
     */
    Host(sdbusplus::bus_t& bus, const char* objPath) :
        sdbusplus::server::object_t<
            sdbusplus::xyz::openbmc_project::Control::server::Host,
            sdbusplus::xyz::openbmc_project::Condition::server::HostFirmware>(
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

    /** @brief Override reads to CurrentFirmwareCondition */
    FirmwareCondition currentFirmwareCondition() const override;

  private:
    /** @brief sdbusplus DBus bus connection. */
    sdbusplus::bus_t& bus;

    /** @brief  Callback function to be invoked by command manager
     *
     *  @detail Conveys the status of the last Host bound command.
     *          Depending on the status,  a CommandComplete or
     *          CommandFailure signal would be sent
     *
     *  @param[in] cmd    - IPMI command and data sent to Host
     *  @param[in] status - Success or Failure
     */
    void commandStatusHandler(IpmiCmdData cmd, bool status);
};

} // namespace command
} // namespace host
} // namespace phosphor
