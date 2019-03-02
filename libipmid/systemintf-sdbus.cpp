#include <ipmid/api.hpp>
#include <memory>
#include <sdbusplus/asio/connection.hpp>

namespace
{
std::unique_ptr<sdbusplus::asio::connection> sdbusp
    __attribute__((init_priority(101)));
} // namespace

void systemIntfSetupSdBus()
{
    // Create a new sdbus connection so it can have a well-known name
    sd_bus* bus = nullptr;
    sd_bus_open_system(&bus);
    if (!bus)
    {
        return;
    }
    auto io = getIoService();
    sdbusp = std::make_unique<sdbusplus::asio::connection>(*io, bus);
}

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
