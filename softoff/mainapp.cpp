// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2016 IBM Corporation

#include "config.h"

#include "softoff.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdeventplus/event.hpp>
#include <sdeventplus/exception.hpp>
#include <xyz/openbmc_project/State/Host/error.hpp>

// Return -1 on any errors to ensure we follow the calling targets OnFailure=
// path
int main(int, char**)
{
    using namespace phosphor::logging;

    // Get a handle to system dbus.
    auto bus = sdbusplus::bus::new_default();

    // Add systemd object manager.
    sdbusplus::server::manager_t(bus, SOFTOFF_OBJPATH);

    // Get default event loop
    auto event = sdeventplus::Event::get_default();

    // Attach the bus to sd_event to service user requests
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);

    // Claim the bus. Delaying it until sending SMS_ATN may result
    // in a race condition between this available and IPMI trying to send
    // message as a response to ack from host.
    bus.request_name(SOFTOFF_BUSNAME);

    // Create the SoftPowerOff object.
    phosphor::ipmi::SoftPowerOff powerObj(bus, event.get(), SOFTOFF_OBJPATH);

    // Wait for client requests until this application has processed
    // at least one successful SoftPowerOff or we timed out
    while (!powerObj.isCompleted() && !powerObj.isTimerExpired())
    {
        try
        {
            event.run(std::nullopt);
        }
        catch (const sdeventplus::SdEventError& e)
        {
            lg2::error("Failure in processing request: {ERROR}", "ERROR", e);
            return 1;
        }
    }

    // Log an error if we timed out after getting Ack for SMS_ATN and before
    // getting the Host Shutdown response
    if (powerObj.isTimerExpired() &&
        (powerObj.responseReceived() ==
         phosphor::ipmi::Base::SoftPowerOff::HostResponse::SoftOffReceived))
    {
        using error =
            sdbusplus::error::xyz::openbmc_project::state::host::SoftOffTimeout;
        using errorMetadata = xyz::openbmc_project::state::host::SoftOffTimeout;
        report<error>(prev_entry<errorMetadata::TIMEOUT_IN_MSEC>());
        return -1;
    }

    return 0;
}
