// Minimal daemon-host symbols required by libipmi20.so at load time.
//
// The libipmi20 provider library references registration entry points, SEL
// helpers, the sd-bus connection singleton, and the legacy `bus` pointer,
// all supplied by the daemon main binary in production. The bounds tests
// only exercise setMgmntCtrlIdStr() via direct calls, so no-op definitions
// satisfy both the static initializers and the dynamic loader.

#include <ipmid/api.h>
#include <systemd/sd-bus.h>

#include <ipmid/handler.hpp>
#include <ipmid/utils.hpp>

// The daemon-side prototypes in ipmid/api.h use C++ linkage (despite the
// .h name); match them exactly so the mangled names line up.
sd_bus* ipmid_get_sd_bus_connection(void)
{
    return nullptr;
}

sd_bus* bus = nullptr;

unsigned short reserveSel(void)
{
    return 0;
}

bool checkSELReservation(unsigned short)
{
    return true;
}

void cancelSELReservation(void) {}

namespace ipmi
{

boost::system::error_code setDbusProperty(
    Context::ptr, const std::string&, const std::string&, const std::string&,
    const std::string&, const Value&)
{
    return {};
}

namespace impl
{

bool registerHandler(int, NetFn, Cmd, Privilege, ::ipmi::HandlerBase::ptr)
{
    return true;
}

bool registerGroupHandler(int, Group, Cmd, Privilege, ::ipmi::HandlerBase::ptr)
{
    return true;
}

void registerFilter(int, ::ipmi::FilterBase::ptr) {}

} // namespace impl
} // namespace ipmi
