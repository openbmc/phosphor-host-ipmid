#pragma once

#include <stdint.h>

#include <cstddef>
#include <ipmid/api.hpp>

// IPMI commands for Chassis net functions.
enum ipmi_netfn_chassis_cmds
{
    IPMI_CMD_GET_CHASSIS_CAP = 0x00,
    // Chassis Status
    IPMI_CMD_CHASSIS_STATUS = 0x01,
    // Chassis Control
    IPMI_CMD_CHASSIS_CONTROL = 0x02,
    IPMI_CMD_CHASSIS_IDENTIFY = 0x04,
    IPMI_CMD_SET_CHASSIS_CAP = 0x05,
    // Get capability bits
    IPMI_CMD_SET_SYS_BOOT_OPTIONS = 0x08,
    IPMI_CMD_GET_SYS_BOOT_OPTIONS = 0x09,
    IPMI_CMD_GET_POH_COUNTER = 0x0F,
};

// Command specific completion codes
enum ipmi_chassis_return_codes
{
    IPMI_OK = 0x0,
    IPMI_CC_PARM_NOT_SUPPORTED = 0x80,
};

// Generic completion codes,
// see IPMI doc section 5.2
enum ipmi_generic_return_codes
{
    IPMI_OUT_OF_SPACE = 0xC4,
};

// Various Chassis operations under a single command.
enum ipmi_chassis_control_cmds : uint8_t
{
    CMD_POWER_OFF = 0x00,
    CMD_POWER_ON = 0x01,
    CMD_POWER_CYCLE = 0x02,
    CMD_HARD_RESET = 0x03,
    CMD_PULSE_DIAGNOSTIC_INTR = 0x04,
    CMD_SOFT_OFF_VIA_OVER_TEMP = 0x05,
};
enum class BootOptionParameter : size_t
{
    BOOT_INFO = 0x4,
    BOOT_FLAGS = 0x5,
    OPAL_NETWORK_SETTINGS = 0x61,
    CHAS_BOOT_OEM1 = 96,
    CHAS_BOOT_OEM2 = 97,
    CHAS_BOOT_OEM3 = 98,
    CHAS_BOOT_OEM4 = 99,
    CHAS_BOOT_OEM5 = 100,
    CHAS_BOOT_OEM6 = 101,
    CHAS_BOOT_OEM7 = 102,
    CHAS_BOOT_OEM8 = 103,
    CHAS_BOOT_OEM9 = 104,
    CHAS_BOOT_OEM10 = 105,
    CHAS_BOOT_OEM11 = 106,
    CHAS_BOOT_OEM12 = 107,
    CHAS_BOOT_OEM13 = 108,
    CHAS_BOOT_OEM14 = 109,
    CHAS_BOOT_OEM15 = 110,
    CHAS_BOOT_OEM16 = 111,
    CHAS_BOOT_OEM17 = 112,
    CHAS_BOOT_OEM18 = 113,
    CHAS_BOOT_OEM19 = 114,
    CHAS_BOOT_OEM20 = 115,
    CHAS_BOOT_OEM21 = 116,
    CHAS_BOOT_OEM22 = 117,
    CHAS_BOOT_OEM23 = 118,
    CHAS_BOOT_OEM24 = 119,
    CHAS_BOOT_OEM25 = 120,
    CHAS_BOOT_OEM26 = 121,
    CHAS_BOOT_OEM27 = 122,
    CHAS_BOOT_OEM28 = 123,
    CHAS_BOOT_OEM29 = 124,
    CHAS_BOOT_OEM30 = 125,
    CHAS_BOOT_OEM31 = 126,
    CHAS_BOOT_OEM32 = 127
};

enum class BootOptionResponseSize : size_t
{
    BOOT_FLAGS = 5,
    OPAL_NETWORK_SETTINGS = 50
};

enum class ChassisIDState : uint8_t
{
    off = 0x0,
    temporaryOn = 0x1,
    indefiniteOn = 0x2,
    reserved = 0x3
};

/** @brief Handle Set System Boot Options OEM Parameters
 *
 *  The Set System Boot Options IPMI command includes a byte range for OEM
 *  Parameters.
 *
 *  @param[in] netfn
 *  @param[in] cmd
 *  @param[in] request
 *  @param[in,out] response
 *  @param[out] data_len
 *  @param[in] context
 *
 *  @return IPMI_CC_OK on success, non-zero otherwise.
 */
ipmi_ret_t ipmi_chassis_set_sys_boot_options_oem(
    ipmi_netfn_t netfn, ipmi_cmd_t cmd, ipmi_request_t request,
    ipmi_response_t response, ipmi_data_len_t data_len, ipmi_context_t context);

/** @brief Handle Get System Boot Options OEM Parameters
 *
 *  The Get System Boot Options IPMI command includes a byte range for OEM
 *  Parameters.
 *
 *  @param[in] netfn
 *  @param[in] cmd
 *  @param[in] request
 *  @param[in,out] response
 *  @param[out] data_len
 *  @param[in] context
 *
 *  @return IPMI_CC_OK on success, non-zero otherwise.
 */
ipmi_ret_t ipmi_chassis_get_sys_boot_options_oem(
    ipmi_netfn_t netfn, ipmi_cmd_t cmd, ipmi_request_t request,
    ipmi_response_t response, ipmi_data_len_t data_len, ipmi_context_t context);
