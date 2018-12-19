#include "command_table.hpp"

#include "main.hpp"
#include "message_handler.hpp"
#include "message_parsers.hpp"
#include "sessions_manager.hpp"

#include <iomanip>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

using namespace phosphor::logging;

namespace command
{

void Table::registerCommand(CommandID inCommand, std::unique_ptr<Entry>&& entry)
{
    auto& command = commandTable[inCommand.command];

    if (command)
    {
        log<level::DEBUG>(
            "Already Registered",
            phosphor::logging::entry("SKIPPED_ENTRY=0x%x",
                                     uint32_t(inCommand.command)));
        return;
    }

    command = std::move(entry);
}

std::vector<uint8_t> Table::executeCommand(uint32_t inCommand,
                                           std::vector<uint8_t>& commandData,
                                           const message::Handler& handler)
{
    using namespace std::chrono_literals;

    std::vector<uint8_t> response;

    auto iterator = commandTable.find(inCommand);

    if (iterator == commandTable.end())
    {
        response.resize(1);
        response[0] = IPMI_CC_INVALID;
    }
    else
    {
        auto start = std::chrono::steady_clock::now();

        response = iterator->second->executeCommand(commandData, handler);

        auto end = std::chrono::steady_clock::now();

        auto elapsedSeconds =
            std::chrono::duration_cast<std::chrono::seconds>(end - start);

        // If command time execution time exceeds 2 seconds, log a time
        // exceeded message
        if (elapsedSeconds > 2s)
        {
            log<level::ERR>("IPMI command timed out",
                            entry("DELAY=%d", elapsedSeconds.count()));
        }
    }
    return response;
}

std::vector<uint8_t>
    NetIpmidEntry::executeCommand(std::vector<uint8_t>& commandData,
                                  const message::Handler& handler)
{
    std::vector<uint8_t> errResponse;

    // Check if the command qualifies to be run prior to establishing a session
    if (!sessionless && (handler.sessionID == session::SESSION_ZERO))
    {
        errResponse.resize(1);
        errResponse[0] = IPMI_CC_INSUFFICIENT_PRIVILEGE;
        log<level::INFO>("Table: Insufficient privilege for command",
                         entry("LUN=%x", int(command.NetFnLun.lun)),
                         entry("NETFN=%x", int(command.NetFnLun.netFn)),
                         entry("CMD=%x", command.cmd));
        return errResponse;
    }

    return functor(commandData, handler);
}

std::vector<uint8_t>
    ProviderIpmidEntry::executeCommand(std::vector<uint8_t>& commandData,
                                       const message::Handler& handler)
{
    std::vector<uint8_t> response(message::parser::MAX_PAYLOAD_SIZE - 1);
    size_t respSize = commandData.size();
    ipmi_ret_t ipmiRC = IPMI_CC_UNSPECIFIED_ERROR;
    std::shared_ptr<session::Session> session =
        std::get<session::Manager&>(singletonPool)
            .getSession(handler.sessionID);

    if (session->curPrivLevel >= Entry::getPrivilege())
    {
        try
        {
            ipmiRC = functor(0, 0, reinterpret_cast<void*>(commandData.data()),
                             reinterpret_cast<void*>(response.data() + 1),
                             &respSize, NULL);
        }
        // IPMI command handlers can throw unhandled exceptions, catch those
        // and return sane error code.
        catch (const std::exception& e)
        {
            log<level::ERR>("Table: Unspecified error for command",
                            entry("EXCEPTION=%s", e.what()),
                            entry("LUN=%x", int(command.NetFnLun.lun)),
                            entry("NETFN=%x", int(command.NetFnLun.netFn)),
                            entry("CMD=%x", command.cmd));
            respSize = 0;
            // fall through
        }
    }
    else
    {
        respSize = 0;
        ipmiRC = IPMI_CC_INSUFFICIENT_PRIVILEGE;
    }
    /*
     * respSize gets you the size of the response data for the IPMI command. The
     * first byte in a response to the IPMI command is the Completion Code.
     * So we are inserting completion code as the first byte and incrementing
     * the response payload size by the size of the completion code.
     */
    response[0] = ipmiRC;
    response.resize(respSize + sizeof(ipmi_ret_t));

    return response;
}

} // namespace command
