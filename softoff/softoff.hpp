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
namespace wdog
{
// TODO Need to put correct interface once we finalize on wdog design
constexpr auto MATCH_TIMEOUT =
    "type='signal',interface='xyz.openbmc_project.State.Watchdog',"
    "path='/xyz/openbmc_project/State/Watchdog/Host',member='Timeout'";

// TODO. Need to put a different patchset to move over to using mapper
constexpr auto CHASSIS_SERVICE = "xyz.openbmc_project.State.Chassis";
constexpr auto CHASSIS_OBJ     = "/xyz/openbmc_project/state/chassis0";
constexpr auto CHASSIS_INTF    = "xyz.openbmc_project.State.Chassis";

// Property and the desired value
constexpr auto CHASSIS_OFF   = "xyz.openbmc_project.State.Chassis.Transition.Off";
constexpr auto PROPERTY_INTF = "org.freedesktop.DBus.Properties";
} // namespace wdog

/** @class SoftPowerOff
 *  @brief Responsible for coordinating Host SoftPowerOff operation
 */
class SoftPowerOff : public sdbusplus::server::object::object<
    sdbusplus::xyz::openbmc_project::Ipmi::Internal::server::SoftPowerOff>
{
    public:
        SoftPowerOff() = delete;
        ~SoftPowerOff() = default;
        SoftPowerOff(const SoftPowerOff&) = delete;
        SoftPowerOff& operator=(const SoftPowerOff&) = delete;
        SoftPowerOff(SoftPowerOff&&) = delete;
        SoftPowerOff& operator=(SoftPowerOff&&) = delete;

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
            bus(bus),
            wdogTimeOut(bus, wdog::MATCH_TIMEOUT, handleTimeOut, this)
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

        /** @brief When set to true, this application can terminate. */
        static bool completed;

    private:
        /** @brief Callback function on watchdog timeout
         *
         *  On getting the signal, initiate the hard power off request
         *
         *  @param[in] msg        - Data associated with subscribed signal
         *  @param[in] userData   - Pointer to this object instance
         *  @param[in] retError   - Return error data if any
         *
         */
        static int handleTimeOut(sd_bus_message* msg,
                                 void* userData,
                                 sd_bus_error* retError);

        /* @brief sdbusplus handle */
        sdbusplus::bus::bus& bus;

        /** @brief Used to subscribe to watchdog timeout events */
        sdbusplus::server::match::match wdogTimeOut;
};
} // namespace ipmi
} // namespace phosphor
