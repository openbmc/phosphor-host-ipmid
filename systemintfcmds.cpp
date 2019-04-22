#include "config.h"

#include "systemintfcmds.hpp"

#include "host-cmd-manager.hpp"
#include "host-interface.hpp"

#include <cstring>
#include <ipmid-host/cmd.hpp>
#include <ipmid/api.hpp>

void register_netfn_app_functions() __attribute__((constructor));

using namespace sdbusplus::xyz::openbmc_project::Control::server;

// For accessing Host command manager
using cmdManagerPtr = std::unique_ptr<phosphor::host::command::Manager>;
extern cmdManagerPtr& ipmid_get_host_cmd_manager();

// global enables
// bit0   - Message Receive Queue enable
// bit1   - Enable Event Message Buffer Full Interrupt
// bit2   - Enable Event Message Buffer
// bit3   - Enable System Event Logging
// bit4   - reserved
// bit5-7 - OEM 0~2 enables
static constexpr uint8_t selEnable = 0x08;
static constexpr uint8_t recvMsgQueueEnable = 0x01;
static constexpr uint8_t globalEnablesDefault = selEnable | recvMsgQueueEnable;

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
ipmi::RspType<uint8_t> ipmiAppGetMessageFlags()
{
    // From IPMI spec V2.0 for Get Message Flags Command :
    // bit:[1] from LSB : 1b = Event Message Buffer Full.
    // Return as 0 if Event Message Buffer is not supported,
    // or when the Event Message buffer is disabled.
    // This path is used to communicate messages to the host
    // from within the phosphor::host::command::Manager
    constexpr uint8_t setEventMsgBufferFull = 0x2;
    return ipmi::responseSuccess(setEventMsgBufferFull);
}

ipmi_ret_t ipmi_app_get_bmc_global_enables(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                           ipmi_request_t request,
                                           ipmi_response_t response,
                                           ipmi_data_len_t data_len,
                                           ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    if (0 != *data_len)
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    *data_len = sizeof(globalEnablesDefault);
    *reinterpret_cast<uint8_t*>(response) = globalEnablesDefault;
    return rc;
}

ipmi_ret_t ipmi_app_set_bmc_global_enables(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                           ipmi_request_t request,
                                           ipmi_response_t response,
                                           ipmi_data_len_t data_len,
                                           ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;

    uint8_t reqMask = *reinterpret_cast<uint8_t*>(request);
    if (sizeof(reqMask) != *data_len)
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *data_len = 0;
    // Recv Message Queue and SEL are enabled by default.
    // Event Message buffer are disabled by default (not supported).
    // Any request that try to change the mask will be rejected
    if (reqMask != (selEnable | recvMsgQueueEnable))
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
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

void register_netfn_app_functions()
{

    // <Read Event Message Buffer>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_READ_EVENT, NULL,
                           ipmi_app_read_event, SYSTEM_INTERFACE);

    // <Set BMC Global Enables>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_SET_BMC_GLOBAL_ENABLES, NULL,
                           ipmi_app_set_bmc_global_enables, SYSTEM_INTERFACE);

    // <Get BMC Global Enables>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_BMC_GLOBAL_ENABLES, NULL,
                           ipmi_app_get_bmc_global_enables, SYSTEM_INTERFACE);

    // <Get Message Flags>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdGetMessageFlags, ipmi::Privilege::Admin,
                          ipmiAppGetMessageFlags);

    // Create new xyz.openbmc_project.host object on the bus
    auto objPath = std::string{CONTROL_HOST_OBJ_MGR} + '/' + HOST_NAME + '0';

    std::unique_ptr<sdbusplus::asio::connection>& sdbusp =
        ipmid_get_sdbus_plus_handler();

    // Add sdbusplus ObjectManager.
    objManager = std::make_unique<sdbusplus::server::manager::manager>(
        *sdbusp, CONTROL_HOST_OBJ_MGR);

    host = std::make_unique<phosphor::host::command::Host>(*sdbusp,
                                                           objPath.c_str());
    sdbusp->request_name(CONTROL_HOST_BUSNAME);

    return;
}
