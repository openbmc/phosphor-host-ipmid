#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <systemd/sd-bus.h>
#include <mapper.h>
#include "host-ipmid/ipmid-api.h"
#include "host-interface.hpp"
#include <config.h>

void register_host_services() __attribute__((constructor));

// OpenBMC Host IPMI dbus framework
const char  *object_name   =  "/org/openbmc/HostIpmi/1";
const char  *intf_name     =  "org.openbmc.HostIpmi";

//------------------------------------------------------
// Called by IPMID as part of the start up
// -----------------------------------------------------
int start_host_service(sd_bus *bus, sd_bus_slot *slot)
{
    int rc = 0;
    return rc < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

//------------------------------------------------------
// Callback register function
// -----------------------------------------------------
void register_host_services()
{
    // Gets a hook onto SYSTEM bus used by host-ipmid
    sd_bus *bus = ipmid_get_sd_bus_connection();

    // Gets a hook onto SYSTEM bus slot used by host-ipmid
    sd_bus_slot *ipmid_slot = ipmid_get_sd_bus_slot();

    //start_host_service(bus, ipmid_slot);
    start_host_service(bus, ipmid_slot);

    static auto sdbus = sdbusplus::bus::bus(sd_bus_ref(bus));

    // Create new xyz.openbmc_project.host object on the bus
    auto objPathInst = std::string{CONTROL_HOST_OBJPATH} + '0';

    // Add sdbusplus ObjectManager.
    sdbusplus::server::manager::manager objManager(sdbus, objPathInst.c_str());

    phosphor::host::Host host(sdbus, objPathInst.c_str());

    sdbus.request_name(CONTROL_HOST_BUSNAME);
}
