#include <array>
#include <boost/asio/signal_set.hpp>
#include <ipmid/api.hpp>
#include <memory>

namespace
{
// SIGRTMAX is defined as a non-constexpr function call and thus cannot be used
// as an array size. Get around this by making a vector and resizing it the
// first time it is needed
std::vector<std::unique_ptr<boost::asio::signal_set>> signals;
} // namespace

void registerSignalHandler(
    int signalNumber,
    std::function<void(const boost::system::error_code&, int)> handler)
{
    if (signalNumber >= SIGRTMAX)
    {
        return;
    }

    if (signals.empty())
    {
        signals.resize(SIGRTMAX);
    }

    if (!signals[signalNumber])
    {
        signals[signalNumber] =
            std::make_unique<boost::asio::signal_set>(*getIoContext());
    }
    signals[signalNumber]->async_wait(
        std::forward<
            std::function<void(const boost::system::error_code&, int)>>(
            handler));
}
