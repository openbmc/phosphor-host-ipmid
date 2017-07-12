#include <memory>
#include <sdbusplus/bus.hpp>
#include "host-cmd-manager.hpp"

// Need this to use new sdbusplus compatible interfaces
using sdbusPtr =  std::unique_ptr<sdbusplus::bus::bus>;
extern sdbusPtr sdbusp;
extern sdbusPtr& ipmid_get_sdbus_plus_handler();

// Global Host Bound Command manager
using cmdManagerPtr = std::unique_ptr<phosphor::host::command::Manager>;
extern cmdManagerPtr cmdManager;
extern cmdManagerPtr& ipmid_get_cmd_manager();
