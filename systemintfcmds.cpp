#include "config.h"

#include "systemintfcmds.hpp"

#include "host-cmd-manager.hpp"
#include "host-interface.hpp"

#include <ipmid/api.h>

#include <cstring>
#include <ipmid-host/cmd.hpp>

void register_netfn_app_functions() __attribute__((constructor));

using namespace sdbusplus::xyz::openbmc_project::Control::server;

// For accessing Host command manager
using cmdManagerPtr = std::unique_ptr<phosphor::host::command::Manager>;
extern cmdManagerPtr& ipmid_get_host_cmd_manager();

//-------------------------------------------------------------------
// Called by Host post response from Get_Message_Flags
//-------------------------------------------------------------------
ipmi_ret_t ipmi_app_read_event(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                               ipmi_request_t request, ipmi_response_t response,
                               ipmi_data_len_t data_len, ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;

    struct oem_sel_timestamped oem_sel = {0};
    *data_len = sizeof(struct oem_sel_timestamped);

    // either id[0] -or- id[1] can be filled in. We will use id[0]
    oem_sel.id[0] = SEL_OEM_ID_0;
    oem_sel.id[1] = SEL_OEM_ID_0;
    oem_sel.type = SEL_RECORD_TYPE_OEM;

    // Following 3 bytes are from IANA Manufactre_Id field. See below
    oem_sel.manuf_id[0] = 0x41;
    oem_sel.manuf_id[1] = 0xA7;
    oem_sel.manuf_id[2] = 0x00;

    // per IPMI spec NetFuntion for OEM
    oem_sel.netfun = 0x3A;

    // Read from the Command Manager queue. What gets returned is a
    // pair of <command, data> that can be directly used here
    auto hostCmd = ipmid_get_host_cmd_manager()->getNextCommand();
    oem_sel.cmd = hostCmd.first;
    oem_sel.data[0] = hostCmd.second;

    // All '0xFF' since unused.
    std::memset(&oem_sel.data[1], 0xFF, 3);

    // Pack the actual response
    std::memcpy(response, &oem_sel, *data_len);
    return rc;
}

//---------------------------------------------------------------------
// Called by Host on seeing a SMS_ATN bit set. Return a hardcoded
// value of 0x2 indicating we need Host read some data.
//-------------------------------------------------------------------
ipmi_ret_t ipmi_app_get_msg_flags(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                  ipmi_request_t request,
                                  ipmi_response_t response,
                                  ipmi_data_len_t data_len,
                                  ipmi_context_t context)
{
    // Generic return from IPMI commands.
    ipmi_ret_t rc = IPMI_CC_OK;

    // From IPMI spec V2.0 for Get Message Flags Command :
    // bit:[1] from LSB : 1b = Event Message Buffer Full.
    // Return as 0 if Event Message Buffer is not supported,
    // or when the Event Message buffer is disabled.
    // TODO. For now. assume its not disabled and send "0x2" anyway:

    uint8_t set_event_msg_buffer_full = 0x2;
    *data_len = sizeof(set_event_msg_buffer_full);

    // Pack the actual response
    std::memcpy(response, &set_event_msg_buffer_full, *data_len);

    return rc;
}

ipmi_ret_t ipmi_app_set_bmc_global_enables(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                           ipmi_request_t request,
                                           ipmi_response_t response,
                                           ipmi_data_len_t data_len,
                                           ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;

    // Event and message logging enabled by default so return for now
#ifdef __IPMI_DEBUG__
    std::printf("IPMI APP SET BMC GLOBAL ENABLES Ignoring for now\n");
#endif

    return rc;
}

namespace
{
// Static storage to keep the object alive during process life
std::unique_ptr<phosphor::host::command::Host> host
    __attribute__((init_priority(101)));
std::unique_ptr<sdbusplus::server::manager::manager> objManager
    __attribute__((init_priority(101)));
} // namespace

#include <unistd.h>
void register_netfn_app_functions()
{

    // <Read Event Message Buffer>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_READ_EVENT, NULL,
                           ipmi_app_read_event, SYSTEM_INTERFACE);

    // <Set BMC Global Enables>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_SET_BMC_GLOBAL_ENABLES, NULL,
                           ipmi_app_set_bmc_global_enables, SYSTEM_INTERFACE);

    // <Get Message Flags>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_MSG_FLAGS, NULL,
                           ipmi_app_get_msg_flags, SYSTEM_INTERFACE);

    // Create new xyz.openbmc_project.host object on the bus
    auto objPath = std::string{CONTROL_HOST_OBJ_MGR} + '/' + HOST_NAME + '0';

    // Add sdbusplus ObjectManager.
    auto& sdbusPlusHandler = ipmid_get_sdbus_plus_handler();
    objManager = std::make_unique<sdbusplus::server::manager::manager>(
        *sdbusPlusHandler, CONTROL_HOST_OBJ_MGR);

    host = std::make_unique<phosphor::host::command::Host>(*sdbusPlusHandler,
                                                           objPath.c_str());
    sdbusPlusHandler->request_name(CONTROL_HOST_BUSNAME);

    return;
}
