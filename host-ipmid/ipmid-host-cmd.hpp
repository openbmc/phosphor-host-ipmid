#include <memory>
#include <sdbusplus/bus.hpp>
#include "host-cmd-manager.hpp"

// Need this to use new sdbusplus compatible interfaces
extern std::unique_ptr<sdbusplus::bus::bus> sdbusp;

// Global Host Bound Command manager
extern std::unique_ptr<phosphor::host::command::Manager> cmdManager;
