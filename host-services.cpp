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
void register_host_services()
{
    // Gets a hook onto SYSTEM bus used by host-ipmid
    sd_bus *bus = ipmid_get_sd_bus_connection();

    static auto sdbus = sdbusplus::bus::bus(sd_bus_ref(bus));

    // Create new xyz.openbmc_project.host object on the bus
    auto objPathInst = std::string{CONTROL_HOST_OBJPATH} + '0';

    // Add sdbusplus ObjectManager.
    sdbusplus::server::manager::manager objManager(sdbus, objPathInst.c_str());

    static phosphor::host::Host host(sdbus, objPathInst.c_str());

    sdbus.request_name(CONTROL_HOST_BUSNAME);

}
