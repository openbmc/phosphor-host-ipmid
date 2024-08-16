#include "sol_manager.hpp"

#include "main.hpp"
#include "sol_context.hpp"

#include <sys/socket.h>
#include <sys/un.h>

#include <boost/asio/basic_stream_socket.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/local/stream_protocol.hpp>
#include <boost/asio/write.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/message/types.hpp>

#include <chrono>
#include <cmath>

constexpr const char* solInterface = "xyz.openbmc_project.Ipmi.SOL";
constexpr const char* solPath = "/xyz/openbmc_project/ipmi/sol/";
constexpr const char* PROP_INTF = "org.freedesktop.DBus.Properties";

namespace sol
{

std::unique_ptr<sdbusplus::bus::match_t> matchPtrSOL(nullptr);
std::unique_ptr<sdbusplus::bus::match_t> solConfPropertiesSignal(nullptr);

void Manager::initConsoleSocket()
{
    // explicit length constructor for NUL-prefixed abstract path
    std::string path(CONSOLE_SOCKET_PATH, CONSOLE_SOCKET_PATH_LEN);
    boost::asio::local::stream_protocol::endpoint ep(path);
    consoleSocket =
        std::make_unique<boost::asio::local::stream_protocol::socket>(*io);
    consoleSocket->connect(ep);
}

void Manager::consoleInputHandler()
{
    boost::system::error_code ec;
    boost::asio::socket_base::bytes_readable cmd(true);
    consoleSocket->io_control(cmd, ec);
    size_t readSize;
    if (!ec)
    {
        readSize = cmd.get();
    }
    else
    {
        lg2::error(
            "Reading ready count from host console socket failed: {ERROR}",
            "ERROR", ec.value());
        return;
    }
    std::vector<uint8_t> buffer(readSize);
    ec.clear();
    size_t readDataLen =
        consoleSocket->read_some(boost::asio::buffer(buffer), ec);
    if (ec)
    {
        lg2::error("Reading from host console socket failed: {ERROR}", "ERROR",
                   ec.value());
        return;
    }

    // Update the Console buffer with data read from the socket
    buffer.resize(readDataLen);
    dataBuffer.write(buffer);
}

int Manager::writeConsoleSocket(const std::vector<uint8_t>& input,
                                bool breakFlag) const
{
    boost::system::error_code ec;
    if (breakFlag)
    {
        consoleSocket->send(boost::asio::buffer(input), MSG_OOB, ec);
    }
    else
    {
        consoleSocket->send(boost::asio::buffer(input), 0, ec);
    }

    return ec.value();
}

void Manager::startHostConsole()
{
    if (!consoleSocket)
    {
        initConsoleSocket();
    }

    // Register callback to close SOL session for disable SSH SOL
    if (matchPtrSOL == nullptr)
    {
        registerSOLServiceChangeCallback();
    }

    consoleSocket->async_wait(boost::asio::socket_base::wait_read,
                              [this](const boost::system::error_code& ec) {
                                  if (!ec)
                                  {
                                      consoleInputHandler();
                                      startHostConsole();
                                  }
                              });
} // namespace sol

void Manager::stopHostConsole()
{
    if (consoleSocket)
    {
        consoleSocket->cancel();
        consoleSocket.reset();
    }
}

void Manager::updateSOLParameter(uint8_t channelNum)
{
    std::variant<uint8_t, bool> value;
    sdbusplus::bus_t dbus(ipmid_get_sd_bus_connection());
    static std::string solService{};
    ipmi::PropertyMap properties;
    std::string ethdevice = ipmi::getChannelName(channelNum);
    std::string solPathWitheEthName = solPath + ethdevice;
    if (solService.empty())
    {
        try
        {
            solService =
                ipmi::getService(dbus, solInterface, solPathWitheEthName);
        }
        catch (const std::runtime_error& e)
        {
            solService.clear();
            lg2::error("Get SOL service failed: {ERROR}", "ERROR", e);
            return;
        }
    }
    try
    {
        properties = ipmi::getAllDbusProperties(
            dbus, solService, solPathWitheEthName, solInterface);
    }
    catch (const std::runtime_error& e)
    {
        lg2::error("Setting sol parameter: {ERROR}", "ERROR", e);
        return;
    }

    progress = std::get<uint8_t>(properties["Progress"]);

    enable = std::get<bool>(properties["Enable"]);

    forceEncrypt = std::get<bool>(properties["ForceEncryption"]);

    forceAuth = std::get<bool>(properties["ForceAuthentication"]);

    solMinPrivilege = static_cast<session::Privilege>(
        std::get<uint8_t>(properties["Privilege"]));

    accumulateInterval =
        std::get<uint8_t>((properties["AccumulateIntervalMS"])) *
        sol::accIntervalFactor * 1ms;

    sendThreshold = std::get<uint8_t>(properties["Threshold"]);

    retryCount = std::get<uint8_t>(properties["RetryCount"]);

    retryInterval = std::get<uint8_t>(properties["RetryIntervalMS"]) *
                    sol::retryIntervalFactor * 1ms;

    return;
}

void Manager::startPayloadInstance(uint8_t payloadInstance,
                                   session::SessionID sessionID)
{
    if (payloadMap.empty())
    {
        try
        {
            startHostConsole();
        }
        catch (const std::exception& e)
        {
            lg2::error(
                "Encountered exception when starting host console. Hence stopping host console: {ERROR}",
                "ERROR", e);
            stopHostConsole();
            throw;
        }
    }

    // Create the SOL Context data for payload instance
    std::shared_ptr<Context> context = Context::makeContext(
        io, retryCount, sendThreshold, payloadInstance, sessionID);

    payloadMap.emplace(payloadInstance, std::move(context));
}

void Manager::stopPayloadInstance(uint8_t payloadInstance)
{
    auto iter = payloadMap.find(payloadInstance);
    if (iter == payloadMap.end())
    {
        throw std::runtime_error("SOL Payload instance not found ");
    }

    payloadMap.erase(iter);

    if (payloadMap.empty())
    {
        stopHostConsole();

        dataBuffer.erase(dataBuffer.size());
    }
}

void Manager::stopAllPayloadInstance()
{
    // Erase all payload instance
    payloadMap.erase(payloadMap.begin(), payloadMap.end());

    stopHostConsole();

    dataBuffer.erase(dataBuffer.size());
}

void registerSOLServiceChangeCallback()
{
    using namespace sdbusplus::bus::match::rules;
    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};
    try
    {
        auto servicePath = ipmi::getDbusObject(
            bus, "xyz.openbmc_project.Control.Service.Attributes",
            "/xyz/openbmc_project/control/service", "_6fbmc_2dconsole");

        if (!std::empty(servicePath.first))
        {
            matchPtrSOL = std::make_unique<sdbusplus::bus::match_t>(
                bus,
                path_namespace(servicePath.first) +
                    "arg0namespace='xyz.openbmc_project.Control.Service."
                    "Attributes'"
                    ", " +
                    type::signal() + member("PropertiesChanged") +
                    interface("org.freedesktop.DBus.Properties"),
                [](sdbusplus::message_t& msg) {
                    std::string intfName;
                    std::map<std::string, std::variant<bool>> properties;
                    msg.read(intfName, properties);

                    const auto it = properties.find("Enabled");
                    if (it != properties.end())
                    {
                        const bool* state = std::get_if<bool>(&it->second);

                        if (state != nullptr && *state == false)
                        {
                            // Stop all the payload session.
                            sol::Manager::get().stopAllPayloadInstance();
                        }
                    }
                });
        }
    }
    catch (const sdbusplus::exception_t& e)
    {
        lg2::error(
            "Failed to get service path in registerSOLServiceChangeCallback: {ERROR}",
            "ERROR", e);
    }
}

void procSolConfChange(sdbusplus::message_t& msg)
{
    using SolConfVariant = std::variant<bool, uint8_t>;
    using SolConfProperties =
        std::vector<std::pair<std::string, SolConfVariant>>;

    std::string iface;
    SolConfProperties properties;

    try
    {
        msg.read(iface, properties);
    }
    catch (const std::exception& e)
    {
        lg2::error("procSolConfChange get properties FAIL: {ERROR}", "ERROR",
                   e);
        return;
    }

    for (const auto& prop : properties)
    {
        if (prop.first == "Progress")
        {
            sol::Manager::get().progress = std::get<uint8_t>(prop.second);
        }
        else if (prop.first == "Enable")
        {
            sol::Manager::get().enable = std::get<bool>(prop.second);
        }
        else if (prop.first == "ForceEncryption")
        {
            sol::Manager::get().forceEncrypt = std::get<bool>(prop.second);
        }
        else if (prop.first == "ForceAuthentication")
        {
            sol::Manager::get().forceAuth = std::get<bool>(prop.second);
        }
        else if (prop.first == "Privilege")
        {
            sol::Manager::get().solMinPrivilege =
                static_cast<session::Privilege>(std::get<uint8_t>(prop.second));
        }
        else if (prop.first == "AccumulateIntervalMS")
        {
            sol::Manager::get().accumulateInterval =
                std::get<uint8_t>(prop.second) * sol::accIntervalFactor * 1ms;
        }
        else if (prop.first == "Threshold")
        {
            sol::Manager::get().sendThreshold = std::get<uint8_t>(prop.second);
        }
        else if (prop.first == "RetryCount")
        {
            sol::Manager::get().retryCount = std::get<uint8_t>(prop.second);
        }
        else if (prop.first == "RetryIntervalMS")
        {
            sol::Manager::get().retryInterval =
                std::get<uint8_t>(prop.second) * sol::retryIntervalFactor * 1ms;
        }
    }
}

void registerSolConfChangeCallbackHandler(std::string channel)
{
    if (solConfPropertiesSignal == nullptr)
    {
        using namespace sdbusplus::bus::match::rules;
        sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};
        try
        {
            auto servicePath = solPath + channel;

            solConfPropertiesSignal = std::make_unique<sdbusplus::bus::match_t>(
                bus, propertiesChangedNamespace(servicePath, solInterface),
                procSolConfChange);
        }
        catch (const sdbusplus::exception_t& e)
        {
            lg2::error(
                "Failed to get service path in registerSolConfChangeCallbackHandler, channel: {CHANNEL}, error: {ERROR}",
                "CHANNEL", channel, "ERROR", e);
        }
    }
    return;
}

} // namespace sol
