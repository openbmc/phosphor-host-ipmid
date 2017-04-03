#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <systemd/sd-bus.h>
#include <mapper.h>
#include "host-ipmid/ipmid-api.h"
#include "host-interface.hpp"
#include <config.h>

void register_host_services() __attribute__((constructor));

//------------------------------------------------------
// Callback register function
// -----------------------------------------------------

// Globals to keep the object alive during process life
std::unique_ptr<sdbusplus::bus::bus> sdbus = nullptr;
std::unique_ptr<phosphor::host::Host> host = nullptr;

void register_host_services()
{
    // Gets a hook onto SYSTEM bus used by host-ipmid
    sd_bus *bus = ipmid_get_sd_bus_connection();

    sdbus = std::make_unique<sdbusplus::bus::bus>(bus);

    // Create new xyz.openbmc_project.host object on the bus
    auto objPathInst = std::string{CONTROL_HOST_OBJPATH} + '0';

    // Add sdbusplus ObjectManager.
    sdbusplus::server::manager::manager objManager(*sdbus.get(),
                                                   objPathInst.c_str());

    // Get the sd_events pointer
    auto events = ipmid_get_sd_event_connection();

    host = std::make_unique<phosphor::host::Host>(*sdbus.get(),
                                                  objPathInst.c_str(),
												  events);

    (*sdbus.get()).request_name(CONTROL_HOST_BUSNAME);

}

phosphor::host::Host::Command getNextCmd()
{
    return(host.get()->getNextCommand());
}
