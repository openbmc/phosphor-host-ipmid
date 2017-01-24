#pragma once

#include <string>
#include <fstream>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include "xyz/openbmc_project/Ipmi/Internal/SoftPowerOff/server.hpp"
namespace phosphor
{
namespace ipmi
{

/** @class SoftPowerOff
 *  @brief Responsible for coordinating Host SoftPowerOff operation
 */
class SoftPowerOff : public sdbusplus::server::object::object<
    sdbusplus::xyz::openbmc_project::Ipmi::Internal::server::SoftPowerOff>
{
    public:
        /** @brief Constructs SoftPowerOff object.
         *
         *  @param[in] bus       - system dbus handler
         *  @param[in] objPath   - The Dbus path that hosts SoftPowerOff function
         */
        SoftPowerOff(sdbusplus::bus::bus& bus,
                     const char* objPath) :
            sdbusplus::server::object::object<
                sdbusplus::xyz::openbmc_project::Ipmi::Internal
                                               ::server::SoftPowerOff>(
                                               bus, objPath),
            bus(bus)
        {
            // Nothing to do here
        }

        /** @brief Sends SMS_ATN to host to initiate soft power off process.
         *         After sending the SMS_ATN, starts a watchdog timer for 30
         *         seconds and expects a initial response from the host.
         *         After receiving the initial response, starts another watchdog
         *         timer for 30 minutes to let host do a clean shutdown of
         *         partitions. When the second response is received from the
         *         host, it indicates that BMC can do a power off.
         *         If BMC fails to get any response, then a hard power off would
         *         be foced.
         *
         *  @param[in] value     - If true, do the action mentioned above
         */
        bool initiate(bool value) override;

        /** @brief Called by IPMI provider as part of response received to
         *         SoftPowerOff process.
         *
         *  @param[in] value - Type of response received within soft power
         *                     off protocol. This could be either of below:
         *                     'SoftOffReceived' or 'PartitionsShutdown'.
         *                     A 'SoftOffReceived' indicates that host has
         *                     received the SMS_ATN that is sent by the above
         *                     'initiate' call.
         *                     A 'PartitionsShutdown' indicates that host has
         *                     shutdown all the partitions and BMC can do a
         *                     power off operation.
         */
        HostResponse responseReceived(HostResponse value) override;

    private:
        /* @brief sdbusplus handle */
        sdbusplus::bus::bus& bus;
};
} // namespace ipmi
} // namespace phosphor
