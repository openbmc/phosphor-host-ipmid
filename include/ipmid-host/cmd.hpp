#include <ipmid-host/cmd-utils.hpp>
#include <sdbusplus/asio/connection.hpp>

#include <memory>

// Global Host Bound Command manager
extern void ipmid_send_cmd_to_host(phosphor::host::command::CommandHandler&&);
extern std::unique_ptr<sdbusplus::asio::connection>&
    ipmid_get_sdbus_plus_handler();
