#pragma once

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/Ipmi/Internal/SoftPowerOff/server.hpp>
#include "timer.hpp"

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
         *  @param[in] event     - sd_event handler
         *  @param[in] objPath   - The Dbus path hosting SoftPowerOff function
         */
        SoftPowerOff(sdbusplus::bus::bus& bus,
                     sd_event* event,
                     const char* objPath) :
            sdbusplus::server::object::object<
                Base::SoftPowerOff>(bus, objPath, false),
                bus(bus),
                timer(event, timeoutHandler)
        {
            // Initialize the timer
            timer.initialize(this);

            // Need to announce since we may get the response
            // very quickly on SMS_ATN
            emit_object_added();

            // The whole purpose of this application is to send SMS_ATTN
            // and watch for the soft power off to go through. We need the
            // interface added signal emitted before we send SMS_ATN just to
            // attend to lightning fast response from host
            sendSMSAttn();
        }

        /** @brief Tells if the objective of this application is completed */
        inline auto isCompleted()
        {
            return completed;
        }

        /** @brief Tells if the referenced timer is expired or not */
        inline auto isTimerExpired()
        {
            return timer.expired;
        }

        /** @brief overloaded property setter function
         *
         *  @param[in] value - One of SoftOffReceived / HostShutdown
         *
         *  @return Success or exception thrown
         */
        HostResponse responseReceived(HostResponse value) override;

        /** @brief Using the base class's getter method */
        using Base::SoftPowerOff::responseReceived;

        /** @brief Calls to start a timer
         *
         *  @param[in] usec - Time in microseconds
         *
         *  @return Success or exception thrown
         */
        int startTimer(const std::chrono::microseconds& usec);

    private:
        // Need this to send SMS_ATTN
        // TODO : Switch over to using mapper service in a different patch
        static constexpr auto HOST_IPMI_BUS  = "org.openbmc.HostIpmi";
        static constexpr auto HOST_IPMI_OBJ  = "/org/openbmc/HostIpmi/1";
        static constexpr auto HOST_IPMI_INTF = "org.openbmc.HostIpmi";

        /* @brief sdbusplus handle */
        sdbusplus::bus::bus& bus;

        /** @brief Reference to Timer object */
        Timer timer;

        /** @brief Marks the end of life of this application.
         *
         *  This is set to true if host gives appropriate responses
         *  for the sequence of commands.
         */
        bool completed = false;

        /** @brief Callback function when timer goes off
         *
         *  On getting the signal, initiate the hard power off request
         *
         *  @param[in] eventSource - Source of the event
         *  @param[in] usec        - time in micro seconds
         *  @param[in] userData    - User data pointer
         *
         */
        static int timeoutHandler(sd_event_source* eventSource,
                                  uint64_t usec, void* userData);

        /** @brief Sends SMS_ATN to host to initiate soft power off process.
         *
         *  After sending the SMS_ATN, starts a timer for 30
         *  seconds and expects a initial response from the host.
         *  After receiving the initial response, starts another
         *  timer for 30 minutes to let host do a clean shutdown of
         *  partitions. When the second response is received from the
         *  host, it indicates that BMC can do a power off.
         *  If BMC fails to get any response, then a hard power off would
         *  be forced.
         *
         *  @return - Does not return anything. Error will result in exception
         *            being thrown
         */
        void sendSMSAttn();
};
} // namespace ipmi
} // namespace phosphor
