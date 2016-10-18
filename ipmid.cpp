#include <string>
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <assert.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include "ipmid.hpp"
#include <errno.h>
#include "sensorhandler.h"
#include <ipmiwhitelist.hpp>
#include <glog/logging.h>

#include "dbus-impl.hpp"
#include "ipmid-server.hpp"

using std::unique_ptr;
using ipmid::DBus;
using ipmid::DBusBusOperationsImpl;
using ipmid::DBusMessageOperationsImpl;
using ipmid::IpmiContext;
using ipmid::IpmiMessage;
using ipmid::IpmiMessageBus;
using ipmid::IpmiMessageBusImpl;
using ipmid::IpmidServer;
using ipmid::OemGroupRouter;
using ipmid::RootRouter;

FILE *ipmiio, *ipmidbus, *ipmicmddetails;

IpmidServer* ipmid_server;

void print_usage(void) {
  fprintf(stderr, "Options:  [-d mask]\n");
  fprintf(stderr, "    mask : 0x01 - Print ipmi packets\n");
  fprintf(stderr, "    mask : 0x02 - Print DBUS operations\n");
  fprintf(stderr, "    mask : 0x04 - Print ipmi command details\n");
  fprintf(stderr, "    mask : 0xFF - Print all trace\n");
}

// IPMI Spec, shared Reservation ID.
unsigned short g_sel_reserve = 0xFFFF;

unsigned short get_sel_reserve_id(void)
{
    return g_sel_reserve;
}

// DEPRECATED: Please use the IpmiRouter API.
void ipmi_register_callback(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                       ipmi_context_t context, ipmid_callback_t handler)
{
    ipmid_server->mutable_root_router()->RegisterIpmidCallbackT(netfn, cmd, context, handler);
}

//----------------------------------------------------------------------
// handler_select
// Select all the files ending with with .so. in the given diretcory
// @d: dirent structure containing the file name
//----------------------------------------------------------------------
int handler_select(const struct dirent *entry)
{
    // To hold ".so" from entry->d_name;
    char dname_copy[4] = {0};

    // We want to avoid checking for everything and isolate to the ones having
    // .so.* or .so in them.
    // Check for versioned libraries .so.*
    if(strstr(entry->d_name, IPMI_PLUGIN_SONAME_EXTN))
    {
        return 1;
    }
    // Check for non versioned libraries .so
    else if(strstr(entry->d_name, IPMI_PLUGIN_EXTN))
    {
        // It is possible that .so could be anywhere in the string but unlikely
        // But being careful here. Get the base address of the string, move
        // until end and come back 3 steps and that gets what we need.
        strcpy(dname_copy, (entry->d_name + strlen(entry->d_name)-strlen(IPMI_PLUGIN_EXTN)));
        if(strcmp(dname_copy, IPMI_PLUGIN_EXTN) == 0)
        {
            return 1;
        }
    }
    return 0;
}

// This will do a dlopen of every .so in ipmi_lib_path and will dlopen everything so that they will
// register a callback handler
void ipmi_register_callback_handlers(const char* ipmi_lib_path)
{
    // For walking the ipmi_lib_path
    struct dirent **handler_list;
    int num_handlers = 0;

    // This is used to check and abort if someone tries to register a bad one.
    void *lib_handler = NULL;

    if(ipmi_lib_path == NULL)
    {
        fprintf(stderr,"ERROR; No handlers to be registered for ipmi.. Aborting\n");
        assert(0);
    }
    else
    {
        // 1: Open ipmi_lib_path. Its usually "/usr/lib/phosphor-host-ipmid"
        // 2: Scan the directory for the files that end with .so
        // 3: For each one of them, just do a 'dlopen' so that they register
        //    the handlers for callback routines.

        std::string handler_fqdn = ipmi_lib_path;

        // Append a "/" since we need to add the name of the .so. If there is
        // already a .so, adding one more is not any harm.
        handler_fqdn += "/";

        num_handlers = scandir(ipmi_lib_path, &handler_list, handler_select, alphasort);
        if (num_handlers < 0)
            return;

        while(num_handlers--)
        {
            handler_fqdn = ipmi_lib_path;
            handler_fqdn += handler_list[num_handlers]->d_name;
            printf("Registering handler:[%s]\n",handler_fqdn.c_str());

            lib_handler = dlopen(handler_fqdn.c_str(), RTLD_NOW);

            if(lib_handler == NULL)
            {
                fprintf(stderr,"ERROR opening [%s]: %s\n",
                        handler_fqdn.c_str(), dlerror());
            }
            // Wipe the memory allocated for this particular entry.
            free(handler_list[num_handlers]);
        }

        // Done with all registration.
        free(handler_list);
    }

    // TODO : What to be done on the memory that is given by dlopen ?.
    return;
}

// DEPRECATED: Please use IpmidServer or DBus.
sd_bus *ipmid_get_sd_bus_connection(void) {
    return ipmid_server->mutable_dbus()->mutable_sd_bus();
}

// DEPRECATED: Please use IpmidServer or DBus.
sd_bus_slot *ipmid_get_sd_bus_slot(void) {
    return ipmid_server->mutable_dbus()->mutable_sd_bus_slot();
}

int main(int argc, char *argv[])
{
    int r;
    unsigned long tvalue;
    int c;

    google::InitGoogleLogging(argv[0]);
    google::InstallFailureSignalHandler();

    // This file and subsequient switch is for turning on levels
    // of trace
    ipmicmddetails = ipmiio = ipmidbus =  fopen("/dev/null", "w");

    while ((c = getopt (argc, argv, "h:d:")) != -1)
        switch (c) {
            case 'd':
                tvalue =  strtoul(optarg, NULL, 16);
                if (1&tvalue) {
                    ipmiio = stdout;
                }
                if (2&tvalue) {
                    ipmidbus = stdout;
                }
                if (4&tvalue) {
                    ipmicmddetails = stdout;
                }
                break;
            case 'h':
            case '?':
                print_usage();
                return 1;
        }


    LOG(INFO) << "ipmid starting...";
    unique_ptr<DBus> dbus(new DBus(std::make_unique<DBusMessageOperationsImpl>(),
                                   std::make_unique<DBusBusOperationsImpl>()));
    r = dbus->Init();
    CHECK(r >= 0) << "Failed to connect to system bus: " << strerror(-r);

    unique_ptr<RootRouter> root_router(new RootRouter(
        std::make_unique<IpmiMessageBusImpl>(dbus.get())));

    IpmidServer server(std::move(dbus),
                       std::move(root_router),
                       whitelist);
    ipmid_server = &server;
    server.UpdateRestrictedMode();
    LOG(INFO) << "ipmid initialization complete.";

    for (;;) {
        if (server.HandleRequest()) {
          continue;
        }
        server.WaitForRequest();
    }

    return 0;
}
