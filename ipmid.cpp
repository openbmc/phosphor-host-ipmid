#include "config.h"

#include "ipmid.hpp"

#include "host-cmd-manager.hpp"
#include "ipmiwhitelist.hpp"
#include "sensorhandler.hpp"
#include "settings.hpp"

#include <assert.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/time.h>
#include <systemd/sd-bus.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <iostream>
#include <ipmid-host/cmd.hpp>
#include <ipmid/oemrouter.hpp>
#include <iterator>
#include <map>
#include <memory>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/message/types.hpp>
#include <sdbusplus/timer.hpp>
#include <vector>
#include <xyz/openbmc_project/Control/Security/RestrictionMode/server.hpp>

using namespace phosphor::logging;
namespace sdbusRule = sdbusplus::bus::match::rules;
namespace variant_ns = sdbusplus::message::variant_ns;

sd_bus* bus = NULL;
sd_bus_slot* ipmid_slot = NULL;
sd_event* events = nullptr;

// Need this to use new sdbusplus compatible interfaces
sdbusPtr sdbusp;

// Global Host Bound Command manager
using cmdManagerPtr = std::unique_ptr<phosphor::host::command::Manager>;
cmdManagerPtr cmdManager;

// Global timer for network changes
std::unique_ptr<phosphor::Timer> networkTimer = nullptr;

// Command and handler tuple. Used when clients ask the command to be put
// into host message queue
using CommandHandler = phosphor::host::command::CommandHandler;

// Initialise restricted mode to true
bool restricted_mode = true;

FILE *ipmiio, *ipmidbus, *ipmicmddetails;

void print_usage(void)
{
    std::fprintf(stderr, "Options:  [-d mask]\n");
    std::fprintf(stderr, "    mask : 0x01 - Print ipmi packets\n");
    std::fprintf(stderr, "    mask : 0x02 - Print DBUS operations\n");
    std::fprintf(stderr, "    mask : 0x04 - Print ipmi command details\n");
    std::fprintf(stderr, "    mask : 0xFF - Print all trace\n");
}

const char* DBUS_INTF = "org.openbmc.HostIpmi";

const char* FILTER =
    "type='signal',interface='org.openbmc.HostIpmi',member='ReceivedMessage'";

typedef std::pair<ipmi_netfn_t, ipmi_cmd_t> ipmi_fn_cmd_t;
typedef std::pair<ipmid_callback_t, ipmi_context_t> ipmi_fn_context_t;

// Global data structure that contains the IPMI command handler's registrations.
std::map<ipmi_fn_cmd_t, ipmi_fn_context_t> g_ipmid_router_map;

// IPMI Spec, shared Reservation ID.
static unsigned short selReservationID = 0xFFFF;
static bool selReservationValid = false;

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

bool checkSELReservation(unsigned short id)
{
    return (selReservationValid && selReservationID == id);
}

void cancelSELReservation(void)
{
    selReservationValid = false;
}

namespace internal
{

constexpr auto restrictionModeIntf =
    "xyz.openbmc_project.Control.Security.RestrictionMode";

namespace cache
{

std::unique_ptr<settings::Objects> objects = nullptr;

} // namespace cache
} // namespace internal

#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 16
#endif

void hexdump(FILE* s, void* mem, size_t len)
{
    unsigned int i, j;

    for (i = 0;
         i <
         len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0);
         i++)
    {
        /* print offset */
        if (i % HEXDUMP_COLS == 0)
        {
            std::fprintf(s, "0x%06x: ", i);
        }

        /* print hex data */
        if (i < len)
        {
            std::fprintf(s, "%02x ", 0xFF & ((char*)mem)[i]);
        }
        else /* end of block, just aligning for ASCII dump */
        {
            std::fprintf(s, "   ");
        }

        /* print ASCII dump */
        if (i % HEXDUMP_COLS == (HEXDUMP_COLS - 1))
        {
            for (j = i - (HEXDUMP_COLS - 1); j <= i; j++)
            {
                if (j >= len) /* end of block, not really printing */
                {
                    std::fputc(' ', s);
                }
                else if (std::isprint(((char*)mem)[j])) /* printable char */
                {
                    std::fputc(0xFF & ((char*)mem)[j], s);
                }
                else /* other char */
                {
                    std::fputc('.', s);
                }
            }
            std::fputc('\n', s);
        }
    }
}

// Method that gets called by shared libraries to get their command handlers
// registered
void ipmi_register_callback(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                            ipmi_context_t context, ipmid_callback_t handler,
                            ipmi_cmd_privilege_t priv)
{
    // Pack NetFn and Command in one.
    auto netfn_and_cmd = std::make_pair(netfn, cmd);

    // Pack Function handler and Data in another.
    auto handler_and_context = std::make_pair(handler, context);

    // Check if the registration has already been made..
    auto iter = g_ipmid_router_map.find(netfn_and_cmd);
    if (iter != g_ipmid_router_map.end())
    {
        log<level::ERR>("Duplicate registration", entry("NETFN=0x%X", netfn),
                        entry("CMD=0x%X", cmd));
    }
    else
    {
        // This is a fresh registration.. Add it to the map.
        g_ipmid_router_map.emplace(netfn_and_cmd, handler_and_context);
    }

    return;
}

// Looks at the map and calls corresponding handler functions.
ipmi_ret_t ipmi_netfn_router(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len)
{
    // return from the Command handlers.
    ipmi_ret_t rc = IPMI_CC_INVALID;

    // If restricted mode is true and command is not whitelisted, don't
    // execute the command
    if (restricted_mode)
    {
        if (!std::binary_search(whitelist.cbegin(), whitelist.cend(),
                                std::make_pair(netfn, cmd)))
        {
            log<level::ERR>("Net function not whitelisted",
                            entry("NETFN=0x%X", netfn), entry("CMD=0x%X", cmd));
            rc = IPMI_CC_INSUFFICIENT_PRIVILEGE;
            std::memcpy(response, &rc, IPMI_CC_LEN);
            *data_len = IPMI_CC_LEN;
            return rc;
        }
    }

    // Walk the map that has the registered handlers and invoke the approprite
    // handlers for matching commands.
    auto iter = g_ipmid_router_map.find(std::make_pair(netfn, cmd));
    if (iter == g_ipmid_router_map.end())
    {
        /* By default should only print on failure to find wildcard command. */
#ifdef __IPMI_DEBUG__
        log<level::ERR>(
            "No registered handlers for NetFn, trying Wilcard implementation",
            entry("NET_FUN=0x%X", netfn) entry("CMD=0x%X", IPMI_CMD_WILDCARD));
#endif

        // Now that we did not find any specific [NetFn,Cmd], tuple, check for
        // NetFn, WildCard command present.
        iter =
            g_ipmid_router_map.find(std::make_pair(netfn, IPMI_CMD_WILDCARD));
        if (iter == g_ipmid_router_map.end())
        {
            log<level::ERR>("No Registered handlers for NetFn",
                            entry("NET_FUN=0x%X", netfn),
                            entry("CMD=0x%X", IPMI_CMD_WILDCARD));

            // Respond with a 0xC1
            std::memcpy(response, &rc, IPMI_CC_LEN);
            *data_len = IPMI_CC_LEN;
            return rc;
        }
    }

#ifdef __IPMI_DEBUG__
    // We have either a perfect match -OR- a wild card atleast,
    log<level::ERR>("Calling Net function",
                    entry("NET_FUN=0x%X", netfn) entry("CMD=0x%X", cmd));
#endif

    // Extract the map data onto appropriate containers
    auto handler_and_context = iter->second;

    // Creating a pointer type casted to char* to make sure we advance 1 byte
    // when we advance pointer to next's address. advancing void * would not
    // make sense.
    char* respo = &((char*)response)[IPMI_CC_LEN];

    try
    {
        // Response message from the plugin goes into a byte post the base
        // response
        rc = (handler_and_context.first)(netfn, cmd, request, respo, data_len,
                                         handler_and_context.second);
    }
    // IPMI command handlers can throw unhandled exceptions, catch those
    // and return sane error code.
    catch (const std::exception& e)
    {
        log<level::ERR>(e.what(), entry("NET_FUN=0x%X", netfn),
                        entry("CMD=0x%X", cmd));
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        *data_len = 0;
        // fall through
    }
    // Now copy the return code that we got from handler and pack it in first
    // byte.
    std::memcpy(response, &rc, IPMI_CC_LEN);

    // Data length is now actual data + completion code.
    *data_len = *data_len + IPMI_CC_LEN;

    return rc;
}

static int send_ipmi_message(sd_bus_message* req, unsigned char seq,
                             unsigned char netfn, unsigned char lun,
                             unsigned char cmd, unsigned char cc,
                             unsigned char* buf, unsigned char len)
{

    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = NULL, *m = NULL;
    const char *dest, *path;
    int r, pty;

    dest = sd_bus_message_get_sender(req);
    path = sd_bus_message_get_path(req);

    r = sd_bus_message_new_method_call(bus, &m, dest, path, DBUS_INTF,
                                       "sendMessage");
    if (r < 0)
    {
        log<level::ERR>("Failed to add the method object",
                        entry("ERRNO=0x%X", -r));
        return -1;
    }

    // Responses in IPMI require a bit set.  So there ya go...
    netfn |= 0x01;

    // Add the bytes needed for the methods to be called
    r = sd_bus_message_append(m, "yyyyy", seq, netfn, lun, cmd, cc);
    if (r < 0)
    {
        log<level::ERR>("Failed add the netfn and others",
                        entry("ERRNO=0x%X", -r));
        goto final;
    }

    r = sd_bus_message_append_array(m, 'y', buf, len);
    if (r < 0)
    {
        log<level::ERR>("Failed to add the string of response bytes",
                        entry("ERRNO=0x%X", -r));
        goto final;
    }

    // Call the IPMI responder on the bus so the message can be sent to the CEC
    r = sd_bus_call(bus, m, 0, &error, &reply);
    if (r < 0)
    {
        log<level::ERR>("Failed to call the method", entry("DEST=%s", dest),
                        entry("PATH=%s", path), entry("ERRNO=0x%X", -r));
        goto final;
    }

    r = sd_bus_message_read(reply, "x", &pty);
    if (r < 0)
    {
        log<level::ERR>("Failed to get a reply from the method",
                        entry("ERRNO=0x%X", -r));
    }

final:
    sd_bus_error_free(&error);
    m = sd_bus_message_unref(m);
    reply = sd_bus_message_unref(reply);

    return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

void cache_restricted_mode()
{
    restricted_mode = false;
    using namespace sdbusplus::xyz::openbmc_project::Control::Security::server;
    using namespace internal;
    using namespace internal::cache;
    sdbusplus::bus::bus dbus(ipmid_get_sd_bus_connection());
    const auto& restrictionModeSetting =
        objects->map.at(restrictionModeIntf).front();
    auto method = dbus.new_method_call(
        objects->service(restrictionModeSetting, restrictionModeIntf).c_str(),
        restrictionModeSetting.c_str(), "org.freedesktop.DBus.Properties",
        "Get");
    method.append(restrictionModeIntf, "RestrictionMode");
    auto resp = dbus.call(method);
    if (resp.is_method_error())
    {
        log<level::ERR>("Error in RestrictionMode Get");
        // Fail-safe to true.
        restricted_mode = true;
        return;
    }
    sdbusplus::message::variant<std::string> result;
    resp.read(result);
    auto restrictionMode = RestrictionMode::convertModesFromString(
        variant_ns::get<std::string>(result));
    if (RestrictionMode::Modes::Whitelist == restrictionMode)
    {
        restricted_mode = true;
    }
}

static int handle_restricted_mode_change(sd_bus_message* m, void* user_data,
                                         sd_bus_error* ret_error)
{
    cache_restricted_mode();
    return 0;
}

static int handle_ipmi_command(sd_bus_message* m, void* user_data,
                               sd_bus_error* ret_error)
{
    int r = 0;
    unsigned char sequence, netfn, lun, cmd;
    const void* request;
    size_t sz;
    size_t resplen = MAX_IPMI_BUFFER;
    unsigned char response[MAX_IPMI_BUFFER];

    std::memset(response, 0, MAX_IPMI_BUFFER);

    r = sd_bus_message_read(m, "yyyy", &sequence, &netfn, &lun, &cmd);
    if (r < 0)
    {
        log<level::ERR>("Failed to parse signal message",
                        entry("ERRNO=0x%X", -r));
        return -1;
    }

    r = sd_bus_message_read_array(m, 'y', &request, &sz);
    if (r < 0)
    {
        log<level::ERR>("Failed to parse signal message",
                        entry("ERRNO=0x%X", -r));
        return -1;
    }

    std::fprintf(ipmiio,
                 "IPMI Incoming: Seq 0x%02x, NetFn 0x%02x, CMD: 0x%02x \n",
                 sequence, netfn, cmd);
    hexdump(ipmiio, (void*)request, sz);

    // Allow the length field to be used for both input and output of the
    // ipmi call
    resplen = sz;

    // Now that we have parsed the entire byte array from the caller
    // we can call the ipmi router to do the work...
    r = ipmi_netfn_router(netfn, cmd, (void*)request, (void*)response,
                          &resplen);
    if (r != 0)
    {
#ifdef __IPMI_DEBUG__
        log<level::ERR>("ERROR in handling NetFn", entry("ERRNO=0x%X", -r),
                        entry("NET_FUN=0x%X", netfn), entry("CMD=0x%X", cmd));
#endif
        resplen = 0;
    }
    else
    {
        resplen = resplen - 1; // first byte is for return code.
    }

    std::fprintf(ipmiio, "IPMI Response:\n");
    hexdump(ipmiio, (void*)response, resplen);

    // Send the response buffer from the ipmi command
    r = send_ipmi_message(m, sequence, netfn, lun, cmd, response[0],
                          ((unsigned char*)response) + 1, resplen);
    if (r < 0)
    {
        log<level::ERR>("Failed to send the response message");
        return -1;
    }

    return 0;
}

//----------------------------------------------------------------------
// handler_select
// Select all the files ending with with .so. in the given diretcory
// @d: dirent structure containing the file name
//----------------------------------------------------------------------
int handler_select(const struct dirent* entry)
{
    // To hold ".so" from entry->d_name;
    char dname_copy[4] = {0};

    // We want to avoid checking for everything and isolate to the ones having
    // .so.* or .so in them.
    // Check for versioned libraries .so.*
    if (strstr(entry->d_name, IPMI_PLUGIN_SONAME_EXTN))
    {
        return 1;
    }
    // Check for non versioned libraries .so
    else if (strstr(entry->d_name, IPMI_PLUGIN_EXTN))
    {
        // It is possible that .so could be anywhere in the string but unlikely
        // But being careful here. Get the base address of the string, move
        // until end and come back 3 steps and that gets what we need.
        strcpy(dname_copy, (entry->d_name + strlen(entry->d_name) -
                            strlen(IPMI_PLUGIN_EXTN)));
        if (strcmp(dname_copy, IPMI_PLUGIN_EXTN) == 0)
        {
            return 1;
        }
    }
    return 0;
}

// This will do a dlopen of every .so in ipmi_lib_path and will dlopen
// everything so that they will register a callback handler
void ipmi_register_callback_handlers(const char* ipmi_lib_path)
{
    // For walking the ipmi_lib_path
    struct dirent** handler_list;

    // This is used to check and abort if someone tries to register a bad one.
    void* lib_handler = NULL;

    if (ipmi_lib_path == NULL)
    {
        log<level::ERR>("No handlers to be registered for ipmi.. Aborting");
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

        int num_handlers =
            scandir(ipmi_lib_path, &handler_list, handler_select, alphasort);
        if (num_handlers < 0)
            return;

        while (num_handlers--)
        {
            handler_fqdn = ipmi_lib_path;
            handler_fqdn += handler_list[num_handlers]->d_name;
#ifdef __IPMI_DEBUG__
            log<level::DEBUG>("Registering handler",
                              entry("HANDLER=%s", handler_fqdn.c_str()));
#endif

            lib_handler = dlopen(handler_fqdn.c_str(), RTLD_NOW);

            if (lib_handler == NULL)
            {
                log<level::ERR>("ERROR opening",
                                entry("HANDLER=%s", handler_fqdn.c_str()),
                                entry("ERROR=%s", dlerror()));
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

sd_bus* ipmid_get_sd_bus_connection(void)
{
    return bus;
}

sd_event* ipmid_get_sd_event_connection(void)
{
    return events;
}

sd_bus_slot* ipmid_get_sd_bus_slot(void)
{
    return ipmid_slot;
}

EInterfaceIndex getInterfaceIndex(void)
{
    return interfaceKCS;
}

// Calls host command manager to do the right thing for the command
void ipmid_send_cmd_to_host(CommandHandler&& cmd)
{
    return cmdManager->execute(std::move(cmd));
}

cmdManagerPtr& ipmid_get_host_cmd_manager()
{
    return cmdManager;
}

sdbusPtr& ipmid_get_sdbus_plus_handler()
{
    return sdbusp;
}

int main(int argc, char* argv[])
{
    int r;
    unsigned long tvalue;
    int c;

    // This file and subsequient switch is for turning on levels
    // of trace
    ipmicmddetails = ipmiio = ipmidbus = fopen("/dev/null", "w");

    while ((c = getopt(argc, argv, "h:d:")) != -1)
        switch (c)
        {
            case 'd':
                tvalue = strtoul(optarg, NULL, 16);
                if (1 & tvalue)
                {
                    ipmiio = stdout;
                }
                if (2 & tvalue)
                {
                    ipmidbus = stdout;
                }
                if (4 & tvalue)
                {
                    ipmicmddetails = stdout;
                }
                break;
            case 'h':
            case '?':
                print_usage();
                return 1;
        }

    /* Connect to system bus */
    r = sd_bus_default_system(&bus);
    if (r < 0)
    {
        log<level::ERR>("Failed to connect to system bus",
                        entry("ERRNO=0x%X", -r));
        goto finish;
    }

    /* Get an sd event handler */
    r = sd_event_default(&events);
    if (r < 0)
    {
        log<level::ERR>("Failure to create sd_event handler",
                        entry("ERRNO=0x%X", -r));
        goto finish;
    }

    // Now create the Host Bound Command manager. Need sdbusplus
    // to use the generated bindings
    sdbusp = std::make_unique<sdbusplus::bus::bus>(bus);
    sdbusp->request_name("xyz.openbmc_project.Ipmi.Host");

    cmdManager = std::make_unique<phosphor::host::command::Manager>(*sdbusp);

    // Activate OemRouter.
    oem::mutableRouter()->activate();

    // Register all the handlers that provider implementation to IPMI commands.
    ipmi_register_callback_handlers(HOST_IPMI_LIB_PATH);

    // Watch for BT messages
    r = sd_bus_add_match(bus, &ipmid_slot, FILTER, handle_ipmi_command, NULL);
    if (r < 0)
    {
        log<level::ERR>("Failed: sd_bus_add_match", entry("FILTER=%s", FILTER),
                        entry("ERRNO=0x%X", -r));
        goto finish;
    }

    // Attach the bus to sd_event to service user requests
    sd_bus_attach_event(bus, events, SD_EVENT_PRIORITY_NORMAL);

    {
        using namespace internal;
        using namespace internal::cache;
        sdbusplus::bus::bus dbus{bus};
        objects = std::make_unique<settings::Objects>(
            dbus, std::vector<settings::Interface>({restrictionModeIntf}));
        // Initialize restricted mode
        cache_restricted_mode();
        // Wait for changes on Restricted mode
        sdbusplus::bus::match_t restrictedModeMatch(
            dbus,
            sdbusRule::propertiesChanged(
                objects->map.at(restrictionModeIntf).front(),
                restrictionModeIntf),
            handle_restricted_mode_change);

        r = sd_event_loop(events);
    }

finish:
    sd_event_unref(events);
    sd_bus_detach_event(bus);
    sd_bus_slot_unref(ipmid_slot);
    sd_bus_unref(bus);
    return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
