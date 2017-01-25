#pragma once

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include "xyz/openbmc_project/Ipmi/Internal/SoftPowerOff/server.hpp"
#include "timer.hpp"

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
         *  @param[in] objPath   - The Dbus path hosting SoftPowerOff function
         *  @param[in] timer     - sd_event timer object
         */
        SoftPowerOff(sdbusplus::bus::bus& bus,
                     const char* objPath,
                     const Timer& timer) :
            sdbusplus::server::object::object<
                sdbusplus::xyz::openbmc_project::Ipmi::Internal
                                               ::server::SoftPowerOff>(
                                               bus, objPath),
                bus(bus),
                timer(timer),
                completed(false)
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
         */
        void sendSmsAttn();

        /** @brief Tells if the objective of this application is completed */
        inline auto isCompleted()
        {
            return completed;
        }

    private:
        // Need this to send SMS_ATTN
        // TODO : Switch over to using mapper service in a different patch
        static constexpr auto HOST_IPMI_BUS  = "org.openbmc.HostIpmi";
        static constexpr auto HOST_IPMI_OBJ  = "/org/openbmc/HostIpmi/1";
        static constexpr auto HOST_IPMI_INTF = "org.openbmc.HostIpmi";

        /* @brief sdbusplus handle */
        sdbusplus::bus::bus& bus;

        /** @brief Reference to Timer object */
        const Timer& timer;

        /** @brief Marks the end of life of this application.
         *
         *  This is set to true if host gives appropriate responses
         *  for the sequence of commands.
         */
        bool completed;
};
} // namespace ipmi
} // namespace phosphor
