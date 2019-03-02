#include <memory>
#include <sdbusplus/asio/connection.hpp>

namespace
{
std::unique_ptr<sdbusplus::asio::connection> sdbusp
    __attribute__((init_priority(101)));
} // namespace

/**
 * @brief ipmid_get_sdbus_plus_handler is used by some ipmi providers
 *
 * @return: a reference to a unique pointer of the systemd connection
 *          managed by the systemintfcmds code
 */
std::unique_ptr<sdbusplus::asio::connection>& ipmid_get_sdbus_plus_handler()
{
    return sdbusp;
}
