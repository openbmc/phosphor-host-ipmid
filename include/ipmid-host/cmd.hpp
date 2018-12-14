#include <ipmid-host/cmd-utils.hpp>
#include <memory>
#include <sdbusplus/bus.hpp>

// Need this to use new sdbusplus compatible interfaces
using sdbusPtr = std::unique_ptr<sdbusplus::bus::bus>;
extern sdbusPtr& ipmid_get_sdbus_plus_handler();

// Global Host Bound Command manager
extern void ipmid_send_cmd_to_host(phosphor::host::command::CommandHandler&&);
