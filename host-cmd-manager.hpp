#pragma once

#include <tuple>
#include <queue>
#include <sdbusplus/bus.hpp>
#include <timer.hpp>
#include <host-ipmid/ipmid-host-cmd-utils.hpp>

namespace phosphor
{
namespace host
{
namespace command
{

/** @class
 *  @brief Manages commands that are to be sent to Host
 */
class Manager
{
    public:
        Manager() = delete;
        ~Manager() = default;
        Manager(const Manager&) = delete;
        Manager& operator=(const Manager&) = delete;
        Manager(Manager&&) = delete;
        Manager& operator=(Manager&&) = delete;

        /** @brief Constructs Manager object
         *
         *  @param[in] bus   - dbus handler
         *  @param[in] event - pointer to sd_event
         */
        Manager(sdbusplus::bus::bus& bus, sd_event* event);

        /** @detail Extracts the next entry in the queue and returns
         *          Command and data part of it.
         *
         *          Also calls into the registered handlers so that they can now
         *          send the CommandComplete signal since the interface contract
         *          is that we emit this signal once the message has been
         *          passed to the host (which is required when calling this)
         *
         *          Also, if the queue has more commands, then it will alert the
         *          host
         */
        IpmiCmdData getNextCommand();

        /** @detail Pushes the command onto the Queue. If the queue is empty,
         *          then it alerts the Host. If not, then it returns and the API
         *          documented above will handle the commands in Queue.
         *
         *  @param[in] command - tuple of <IPMI command, data, callback>
         */
        void execute(CommandHandler command);

    private:
        /** @brief Check if anything in queue and alert host if so */
        void checkQueueAndAlertHost();

        /** @detail Call back interface on message timeouts to host.
         *          When this happens, a failure message would be sent
         *          to all the commands that are in the Queue and queue
         *          will be purged
         */
        void hostTimeout();

        /** @brief Reference to the dbus handler */
        sdbusplus::bus::bus& bus;

        /** @brief Queue to store the requested commands */
        std::queue<CommandHandler> workQueue{};

        /** @brief Timer for commands to host */
        phosphor::ipmi::Timer timer;
};

} // namespace command
} // namespace host
} // namespace phosphor
