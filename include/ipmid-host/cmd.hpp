#include <ipmid-host/cmd-utils.hpp>
#include <memory>
#include <sdbusplus/bus.hpp>

// Global Host Bound Command manager
extern void ipmid_send_cmd_to_host(phosphor::host::command::CommandHandler&&);
extern std::unique_ptr<sdbusplus::bus::bus>& ipmid_get_sdbus_plus_handler();
