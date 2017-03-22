#include <systemd/sd-bus.h>
#include "host-interface.hpp"

extern "C" int start_host_service(sd_bus *, sd_bus_slot *);
sdbusplus::xyz::openbmc_project::Control::server::Host::Command getNextCmd();
