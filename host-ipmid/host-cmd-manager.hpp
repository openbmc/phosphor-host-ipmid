#pragma once

#include <tuple>
#include <queue>
#include <sdbusplus/bus.hpp>
#include "timer.hpp"

namespace phosphor
{
namespace host
{
namespace command
{

/** @detail After sending SMS_ATN to the Host, Host comes down and asks
 *          why an 'SMS_ATN` was sent.
 *          BMC then sends 'There is a Message to be Read` as reponse.
 *          Host then comes down asks for Message and the specified
 *          commands and data would go as data conforming to IPMI spec.
 *
 *          Refer: 6.13.2 Send Message Command From System Interface
 *          in IPMI V2.0 spec.
 */

/** @brief IPMI command */
using IPMIcmd = uint8_t;

/** @brief Data associated with command */
using Data = uint8_t;

/** @brief <IPMI command, Data> to be sent as payload when Host asks for
 *         the message that can be associated with the previous SMS_ATN
 */
using IpmiCmdData = std::pair<IPMIcmd, Data>;

/** @detail Implementation specific callback function to be invoked
 *          conveying the status of the executed command. Specific
 *          implementations may then broadcast an agreed signal
 */
using CallBack = std::function<void(IpmiCmdData, bool)>;

/** @detail Tuple encapsulating above 2 to enable using Manager by different
 *          implementations. Users of Manager will supply <Ipmi command, Data>
 *          along with the callback handler. Manager will invoke the handler
 *          conveying the status of the command.
 */
using CommandHandler = std::tuple<IpmiCmdData, CallBack>;

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
        Manager(sdbusplus::bus::bus& bus, sd_event* event) :
            bus(bus),
            timer(event, std::bind(&Manager::hostTimeout, this))
        {
            // Nothing to do here.
        }

        /** @brief Extracts the next entry in the queue and returns
         *         Command and data part of it.
         *
         *         Also calls into the registered handlers so that they can now
         *         send the CommandComplete signal since the interface contract
         *         is that we emit this signal once the message has been
         *         passed to the host (which is required when calling this)
         *
         *         Also, if the queue has more commands, then it will alert the
         *         host
         */
        IpmiCmdData getNextCommand();

        /** @brief Pushes the command onto the Queue. If the queue is empty,
         *         then it alerts the Host. If not, then it returns and the API
         *         documented above will handle the commands in Queue.
         *
         *  @param[in] command - tuple of <IPMI command, data, callback>
         */
        void execute(CommandHandler command);

    private:
        /** @brief Check if anything in queue and alert host if so */
        void checkQueueAndAlertHost();

        /** @brief Call back interface on message timeouts to host.
         *         When this happens, a failure message would be sent
         *         to all the commands that are in the Queue and queue
         *         will be purged
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
