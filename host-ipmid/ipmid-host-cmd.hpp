#include "ipmid-host-cmd-utils.hpp"

#include <memory>
#include <sdbusplus/bus.hpp>

// Global Host Bound Command manager
extern void ipmid_send_cmd_to_host(phosphor::host::command::CommandHandler&&);
