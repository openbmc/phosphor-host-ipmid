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
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>

#include <map>
#include <string>
#include <utility>
#include <vector>

// The daemon-side prototypes in ipmid/api.h use C++ linkage (despite the
// .h name); match them exactly so the mangled names line up.
sd_bus* ipmid_get_sd_bus_connection(void)
{
    return nullptr;
}

// Supplied by libchannellayer in production; not linked into this test
// binary to keep the DSO set minimal (see meson.build note).
namespace ipmi
{
std::string getChannelName(uint8_t)
{
    return "test";
}

// The remaining helpers are supplied by libipmid in production. The
// test binary links no project DSOs (see meson.build note), so they are
// stubbed here with their exact production signatures; none of them run
// on the paths under test.

boost::system::error_code getService(
    Context::ptr /*ctx*/, const std::string& /*intf*/,
    const std::string& /*path*/, std::string& /*service*/)
{
    return {};
}

boost::system::error_code getDbusObject(
    Context::ptr /*ctx*/, const std::string& /*interface*/,
    const std::string& /*subtreePath*/, const std::string& /*match*/,
    DbusObjectInfo& /*dbusObject*/)
{
    return {};
}

boost::system::error_code getAllDbusObjects(
    Context::ptr /*ctx*/, const std::string& /*serviceRoot*/,
    const std::string& /*interface*/, const std::string& /*match*/,
    ObjectTree& /*objectTree*/)
{
    return {};
}

boost::system::error_code getAllDbusProperties(
    Context::ptr /*ctx*/, const std::string& /*service*/,
    const std::string& /*objPath*/, const std::string& /*interface*/,
    PropertyMap& /*properties*/)
{
    return {};
}
} // namespace ipmi

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
