#include "main.hpp"
#include <assert.h>
#include <dlfcn.h>
#include <dirent.h>
#include <unistd.h>

#include <iostream>
#include <tuple>

#include <systemd/sd-bus.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>

#include <host-ipmid/ipmid-api.h>
#include "command/guid.hpp"
#include "comm_module.hpp"
#include "command_table.hpp"
#include "message.hpp"
#include "message_handler.hpp"
#include "provider_registration.hpp"
#include "socket_channel.hpp"
#include "sol_module.hpp"

// Tuple of Global Singletons
session::Manager manager;
command::Table table;
eventloop::EventLoop loop;
sol::Manager solManager;

std::tuple<session::Manager&, command::Table&, eventloop::EventLoop&,
        sol::Manager&> singletonPool(manager, table, loop, solManager);

sd_bus* bus = nullptr;

FILE* ipmidbus = nullptr;
unsigned short g_sel_reserve = 0xFFFF;
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
unsigned short get_sel_reserve_id()
{
    return g_sel_reserve;
}

int main(int i_argc, char* i_argv[])
{
    /*
     * Required by apphandler IPMI Provider Library for logging.
     */
    ipmidbus =  fopen("/dev/null", "w");

    // Connect to system bus
    auto rc = sd_bus_open_system(&bus);
    if (rc < 0)
    {
        std::cerr << "Failed to connect to system bus:" << strerror(-rc) <<"\n";
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
    return std::get<eventloop::EventLoop&>(singletonPool).startEventLoop();

finish:
    sd_bus_unref(bus);

    return 0;
}
