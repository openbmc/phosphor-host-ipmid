#include <boost/asio.hpp>
#include <memory>
#include <sdbusplus/asio/connection.hpp>

namespace
{
std::shared_ptr<boost::asio::io_service> ios
    __attribute__((init_priority(101)));

std::shared_ptr<sdbusplus::asio::connection> sdbusp
    __attribute__((init_priority(101)));
} // namespace

void setIoService(std::shared_ptr<boost::asio::io_service> other)
{
    ios = other;
}

std::shared_ptr<boost::asio::io_service> getIoService()
{
    return ios;
}

void setSdBus(std::shared_ptr<sdbusplus::asio::connection> other)
{
    sdbusp = other;
}

std::shared_ptr<sdbusplus::asio::connection> getSdBus()
{
    return sdbusp;
}
