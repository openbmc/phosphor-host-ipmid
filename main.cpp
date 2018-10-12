#include "main.hpp"

#include "comm_module.hpp"
#include "command/guid.hpp"
#include "command_table.hpp"
#include "message.hpp"
#include "message_handler.hpp"
#include "provider_registration.hpp"
#include "socket_channel.hpp"
#include "sol_module.hpp"
#include "timer.hpp"

#include <assert.h>
#include <dirent.h>
#include <dlfcn.h>
#include <host-ipmid/ipmid-api.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>
#include <unistd.h>

#include <iostream>
#include <tuple>

// Tuple of Global Singletons
session::Manager manager;
command::Table table;
eventloop::EventLoop loop;
sol::Manager solManager;

std::tuple<session::Manager&, command::Table&, eventloop::EventLoop&,
           sol::Manager&>
    singletonPool(manager, table, loop, solManager);

sd_bus* bus = nullptr;
sd_event* events = nullptr;

// Global timer for network changes
std::unique_ptr<phosphor::ipmi::Timer> networkTimer = nullptr;

FILE* ipmidbus = nullptr;
static unsigned short selReservationID = 0xFFFF;
static bool selReservationValid = false;
sd_bus_slot* ipmid_slot = nullptr;

/*
 * @brief Required by apphandler IPMI Provider Library
 */
sd_bus* ipmid_get_sd_bus_connection()
{
    return bus;
}

/*
 * @brief Required by apphandler IPMI Provider Library
 */
sd_event* ipmid_get_sd_event_connection()
{
    return events;
}

/*
 * @brief Required by apphandler IPMI Provider Library
 */
unsigned short reserveSel(void)
{
    // IPMI spec, Reservation ID, the value simply increases against each
    // execution of the Reserve SEL command.
    if (++selReservationID == 0)
    {
        selReservationID = 1;
    }
    selReservationValid = true;
    return selReservationID;
}

/*
 * @brief Required by apphandler IPMI Provider Library
 */
bool checkSELReservation(unsigned short id)
{
    return (selReservationValid && selReservationID == id);
}

/*
 * @brief Required by apphandler IPMI Provider Library
 */
void cancelSELReservation(void)
{
    selReservationValid = false;
}

int main(int i_argc, char* i_argv[])
{
    /*
     * Required by apphandler IPMI Provider Library for logging.
     */
    ipmidbus = fopen("/dev/null", "w");

    // Connect to system bus
    auto rc = sd_bus_open_system(&bus);
    if (rc < 0)
    {
        std::cerr << "Failed to connect to system bus:" << strerror(-rc)
                  << "\n";
        goto finish;
    }

    /* Get an sd event handler */
    rc = sd_event_default(&events);
    if (rc < 0)
    {
        std::cerr << "Failure to create sd_event" << strerror(-rc) << "\n";
        goto finish;
    }

    // Register callback to update cache for a GUID change and cache the GUID
    command::registerGUIDChangeCallback();
    cache::guid = command::getSystemGUID();

    // Register all the IPMI provider libraries applicable for net-ipmid
    provider::registerCallbackHandlers(NET_IPMID_LIB_PATH);

    // Register the phosphor-net-ipmid session setup commands
    command::sessionSetupCommands();

    // Register the phosphor-net-ipmid SOL commands
    sol::command::registerCommands();

    // Start Event Loop
    return std::get<eventloop::EventLoop&>(singletonPool)
        .startEventLoop(events);

finish:
    sd_bus_unref(bus);
    sd_event_unref(events);

    return 0;
}
