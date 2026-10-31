// Daemon-side symbols referenced by chassishandler.cpp.
//
// In production these come from the ipmid binary and libipmid. The
// host_network_data test compiles chassishandler.cpp directly and links no
// project DSOs, so each symbol is defined here with its production
// signature. None of them run on the paths under test.

#include <ipmid/api.hpp>
#include <ipmid/handler.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <settings.hpp>

#include <chrono>
#include <memory>
#include <string>
#include <vector>

sd_bus* ipmid_get_sd_bus_connection(void)
{
    return nullptr;
}

std::shared_ptr<sdbusplus::asio::connection> getSdBus()
{
    return nullptr;
}

namespace settings
{
Objects::Objects(sdbusplus::bus_t& bus,
                 const std::vector<Interface>& /*filter*/) : bus(bus)
{}
} // namespace settings

namespace ipmi
{

DbusObjectInfo getDbusObject(
    sdbusplus::bus_t& /*bus*/, const std::string& /*interface*/,
    const std::string& /*subtreePath*/, const std::string& /*match*/)
{
    return {};
}

Value getDbusProperty(
    sdbusplus::bus_t& /*bus*/, const std::string& /*service*/,
    const std::string& /*objPath*/, const std::string& /*interface*/,
    const std::string& /*property*/, std::chrono::microseconds /*timeout*/)
{
    return {};
}

PropertyMap getAllDbusProperties(
    sdbusplus::bus_t& /*bus*/, const std::string& /*service*/,
    const std::string& /*objPath*/, const std::string& /*interface*/,
    std::chrono::microseconds /*timeout*/)
{
    return {};
}

void setDbusProperty(sdbusplus::bus_t& /*bus*/, const std::string& /*service*/,
                     const std::string& /*objPath*/,
                     const std::string& /*interface*/,
                     const std::string& /*property*/, const Value& /*value*/,
                     std::chrono::microseconds /*timeout*/)
{}

std::string getService(sdbusplus::bus_t& /*bus*/, const std::string& /*intf*/,
                       const std::string& /*path*/)
{
    return "test.service";
}

boost::system::error_code getService(
    Context::ptr /*ctx*/, const std::string& /*intf*/,
    const std::string& /*path*/, std::string& service)
{
    service = "test.service";
    return {};
}

boost::system::error_code getSubTree(
    Context::ptr /*ctx*/, const InterfaceList& /*interface*/,
    const std::string& /*subtreePath*/, int32_t /*depth*/,
    ObjectTree& /*objectTree*/)
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

boost::system::error_code setDbusProperty(
    Context::ptr /*ctx*/, const std::string& /*service*/,
    const std::string& /*objPath*/, const std::string& /*interface*/,
    const std::string& /*property*/, const Value& /*value*/)
{
    return {};
}

boost::system::error_code callDbusMethod(
    Context::ptr /*ctx*/, const std::string& /*service*/,
    const std::string& /*objPath*/, const std::string& /*interface*/,
    const std::string& /*method*/)
{
    return {};
}

namespace impl
{
bool registerHandler(int /*prio*/, NetFn /*netFn*/, Cmd /*cmd*/,
                     Privilege /*priv*/, ::ipmi::HandlerBase::ptr /*handler*/)
{
    return true;
}
} // namespace impl

} // namespace ipmi
