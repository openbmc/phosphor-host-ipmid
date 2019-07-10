#pragma once

#include <stdint.h>

#include <iostream>
#include <sstream>
#include <string>

// IPMI commands for App net functions.
enum ipmi_netfn_app_cmds
{
    // Get capability bits
    IPMI_CMD_GET_DEVICE_ID = 0x01,
    IPMI_CMD_GET_SELF_TEST_RESULTS = 0x04,
    IPMI_CMD_SET_ACPI = 0x06,
    IPMI_CMD_GET_ACPI = 0x07,
    IPMI_CMD_GET_DEVICE_GUID = 0x08,
    IPMI_CMD_RESET_WD = 0x22,
    IPMI_CMD_SET_WD = 0x24,
    IPMI_CMD_GET_WD = 0x25,
    IPMI_CMD_GET_CAP_BIT = 0x36,
    IPMI_CMD_GET_SYS_GUID = 0x37,
    IPMI_CMD_SET_CHAN_ACCESS = 0x40,
    IPMI_CMD_GET_CHANNEL_ACCESS = 0x41,
    IPMI_CMD_GET_CHAN_INFO = 0x42,
    IPMI_CMD_GET_CHAN_CIPHER_SUITES = 0x54,
    IPMI_CMD_SET_SYSTEM_INFO = 0x58,
    IPMI_CMD_GET_SYSTEM_INFO = 0x59,
};

enum ipmi_app_sysinfo_params
{
    IPMI_SYSINFO_SET_STATE = 0x00,
    IPMI_SYSINFO_SYSTEM_FW_VERSION = 0x01,
    IPMI_SYSINFO_SYSTEM_NAME = 0x02,
    IPMI_SYSINFO_PRIMARY_OS_NAME = 0x03,
    IPMI_SYSINFO_OS_NAME = 0x04,
    IPMI_SYSINFO_OS_VERSION = 0x05,
    IPMI_SYSINFO_BMC_URL = 0x06,
    IPMI_SYSINFO_OS_HYP_URL = 0x07,
    IPMI_SYSINFO_OEM_START = 0xC0, // Start of range of OEM parameters
};

/**
 * @brief parse session input payload.
 *
 * This function retrives the session id and session handle from the session
 * object path.
 * A valid object path will be in the form
 * "/xyz/openbmc_project/ipmi/session/channel/sessionId_sessionHandle"
 *
 * Ex: "/xyz/openbmc_project/ipmi/session/eth0/12a4567d_8a"
 * SessionId    : 0X12a4567d
 * SessionHandle: 0X8a

 * @param[in] objectPath - session object path
 * @param[in] sessionId - retrived session id will be asigned.
 * @param[in] sessionHandle - retrived session handle will be asigned.
 *
 * @return true if session id and session handle are retrived else returns
 false.
 */
bool parseCloseSessionInputPayload(const std::string& objectPath,
                                   uint32_t& sessionId, uint8_t& sessionHandle)
{
    if (objectPath.empty())
    {
        return false;
    }
    // getting the position of session id and session handle string from
    // object path.
    std::size_t ptrPosition = objectPath.rfind("/");
    uint16_t tempSessionHandle = 0;

    if (ptrPosition != std::string::npos)
    {
        // get the sessionid & session handle string from the session object
        // path Ex: sessionIdString: "12a4567d_8a"
        std::string sessionIdString = objectPath.substr(ptrPosition + 1);
        std::size_t pos = sessionIdString.rfind("_");

        if (pos != std::string::npos)
        {
            // extracting the session handle
            std::string sessionHandleString = sessionIdString.substr(pos + 1);
            // extracting the session id
            sessionIdString = sessionIdString.substr(0, pos);
            // converting session id string  and session handle string to
            // hexadecimal.
            std::stringstream handle(sessionHandleString);
            handle >> std::hex >> tempSessionHandle;
            sessionHandle = tempSessionHandle & 0xFF;
            std::stringstream idString(sessionIdString);
            idString >> std::hex >> sessionId;
            return true;
        }
    }
    return false;
}