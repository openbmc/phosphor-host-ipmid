#include "systemintfcmds.h"
#include "host-ipmid/ipmid-api.h"
#include "config.h"
#include "host-interface.hpp"

#include <stdio.h>
#include <mapper.h>

void register_netfn_app_functions() __attribute__((constructor));

using namespace sdbusplus::xyz::openbmc_project::Control::server;

// Internal function to get next host command
Host::Command getNextHostCmd();

// Notify SofPowerOff application that host is responding to command
void notifySoftOff()
{

    constexpr auto iface          = "org.freedesktop.DBus.Properties";
    constexpr auto soft_off_iface = "xyz.openbmc_project.Ipmi.Internal."
                                    "SoftPowerOff";

    constexpr auto property       = "ResponseReceived";
    constexpr auto value          = "xyz.openbmc_project.Ipmi.Internal."
                                    "SoftPowerOff.HostResponse.SoftOffReceived";
    char *busname = nullptr;

    // Get the system bus where most system services are provided.
    auto bus = ipmid_get_sd_bus_connection();

    // Nudge the SoftPowerOff application that it needs to stop the
    // initial watchdog timer. If we have some errors talking to Soft Off
    // object, get going and do our regular job
    mapper_get_service(bus, SOFTOFF_OBJPATH, &busname);
    if (busname)
    {
        // No error object or reply expected.
        auto r = sd_bus_call_method(bus, busname, SOFTOFF_OBJPATH, iface,
                                 "Set", nullptr, nullptr, "ssv",
                                 soft_off_iface, property, "s", value);
        if (r < 0)
        {
            fprintf(stderr, "Failed to set property in SoftPowerOff object: %s\n",
                    strerror(-r));
        }
        free (busname);
    }
    else
    {
        printf("Soft Power Off object is not available. Ignoring watchdog \
                refresh");
    }
}

//-------------------------------------------------------------------
// Called by Host post response from Get_Message_Flags
//-------------------------------------------------------------------
ipmi_ret_t ipmi_app_read_event(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
        ipmi_request_t request, ipmi_response_t response,
        ipmi_data_len_t data_len, ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;

    printf("IPMI APP READ EVENT command received\n");

    struct oem_sel_timestamped oem_sel = {0};
    *data_len = sizeof(struct oem_sel_timestamped);

    // either id[0] -or- id[1] can be filled in. We will use id[0]
    oem_sel.id[0]   = SEL_OEM_ID_0;
    oem_sel.id[1]   = SEL_OEM_ID_0;
    oem_sel.type    = SEL_RECORD_TYPE_OEM;

    // Following 3 bytes are from IANA Manufactre_Id field. See below
    oem_sel.manuf_id[0]= 0x41;
    oem_sel.manuf_id[1]= 0xA7;
    oem_sel.manuf_id[2]= 0x00;

    // per IPMI spec NetFuntion for OEM
    oem_sel.netfun  = 0x3A;

    // Read from the queue to see what our response is here
    Host::Command hCmd = getNextHostCmd();
    switch (hCmd)
    {
    case Host::Command::SoftOff:
        notifySoftOff();
        oem_sel.cmd     = CMD_POWER;
        oem_sel.data[0] = SOFT_OFF;
        break;
    case Host::Command::Heartbeat:
        oem_sel.cmd     = CMD_HEARTBEAT;
        oem_sel.data[0] = 0x00;
        break;
    }

    // All '0xFF' since unused.
    memset(&oem_sel.data[1], 0xFF, 3);

    // Pack the actual response
    memcpy(response, &oem_sel, *data_len);
    return rc;
}

//---------------------------------------------------------------------
// Called by Host on seeing a SMS_ATN bit set. Return a hardcoded
// value of 0x2 indicating we need Host read some data.
//-------------------------------------------------------------------
ipmi_ret_t ipmi_app_get_msg_flags(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    // Generic return from IPMI commands.
    ipmi_ret_t rc = IPMI_CC_OK;

    printf("IPMI APP GET MSG FLAGS returning with [bit:2] set\n");

    // From IPMI spec V2.0 for Get Message Flags Command :
    // bit:[1] from LSB : 1b = Event Message Buffer Full.
    // Return as 0 if Event Message Buffer is not supported,
    // or when the Event Message buffer is disabled.
    // TODO. For now. assume its not disabled and send "0x2" anyway:

    uint8_t set_event_msg_buffer_full = 0x2;
    *data_len = sizeof(set_event_msg_buffer_full);

    // Pack the actual response
    memcpy(response, &set_event_msg_buffer_full, *data_len);

    return rc;
}

ipmi_ret_t ipmi_app_set_bmc_global_enables(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;

    // Event and message logging enabled by default so return for now
    printf("IPMI APP SET BMC GLOBAL ENABLES Ignoring for now\n");

    return rc;
}

// Globals to keep the object alive during process life
std::unique_ptr<sdbusplus::bus::bus> sdbus = nullptr;
// TODO openbmc/openbmc#1581 - unique_ptr causes seg fault
phosphor::host::Host* host = nullptr;


#include <unistd.h>
void register_netfn_app_functions()
{

    // <Read Event Message Buffer>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_READ_EVENT);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_READ_EVENT, NULL, ipmi_app_read_event,
                           SYSTEM_INTERFACE);

    // <Set BMC Global Enables>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP,
                                            IPMI_CMD_SET_BMC_GLOBAL_ENABLES);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_SET_BMC_GLOBAL_ENABLES, NULL,
                           ipmi_app_set_bmc_global_enables, SYSTEM_INTERFACE);

    // <Get Message Flags>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_GET_MSG_FLAGS);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_MSG_FLAGS, NULL, ipmi_app_get_msg_flags,
                           SYSTEM_INTERFACE);

    // Gets a hook onto SYSTEM bus used by host-ipmid
    sd_bus *bus = ipmid_get_sd_bus_connection();

    sdbus = std::make_unique<sdbusplus::bus::bus>(bus);

    // Create new xyz.openbmc_project.host object on the bus
    auto objPathInst = std::string{CONTROL_HOST_OBJPATH} + '0';

    // Add sdbusplus ObjectManager.
    sdbusplus::server::manager::manager objManager(*sdbus,
                                                   objPathInst.c_str());

    host = new phosphor::host::Host(*sdbus,
                                    objPathInst.c_str());

    sdbus->request_name(CONTROL_HOST_BUSNAME);

    return;
}

Host::Command getNextHostCmd()
{
    return(host->getNextCommand());
}
