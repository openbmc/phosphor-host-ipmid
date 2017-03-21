#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <systemd/sd-bus.h>
#include <mapper.h>
#include "host-ipmid/ipmid-api.h"
#include "host-interface.hpp"

void register_host_services() __attribute__((constructor));

//------------------------------------------------------
// Callback register function
// -----------------------------------------------------
void register_host_services()
{
    // Gets a hook onto SYSTEM bus used by host-ipmid
    sd_bus *bus = ipmid_get_sd_bus_connection();

    // Gets a hook onto SYSTEM bus slot used by host-ipmid
    //sd_bus_slot *ipmid_slot = ipmid_get_sd_bus_slot();

    //start_host_service(bus, ipmid_slot);
    //start_host_service(bus, ipmid_slot);

    static auto sdbus = sdbusplus::bus::bus(sd_bus_ref(bus));

    // Create new xyz.openbmc_project.host object on the bus
    auto objPathInst = std::string{"/xyz/openbmc_project/control/host"} + '0';

    // Add sdbusplus ObjectManager.
    sdbusplus::server::manager::manager objManager(sdbus, objPathInst.c_str());

    static phosphor::host::Host host(sdbus,
                                     objPathInst.c_str());

    sdbus.request_name("xyz.openbmc_project.Control.Host");

}
