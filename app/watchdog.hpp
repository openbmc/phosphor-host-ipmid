#pragma once

#include <ipmid/api.hpp>

/** @brief The RESET watchdog IPMI command.
 */
ipmi::RspType<> ipmiAppResetWatchdogTimer();

/** @brief The SET watchdog IPMI command.
 *
 *  @param[in] netfn
 *  @param[in] cmd
 *  @param[in] request
 *  @param[in,out] response
 *  @param[out] data_len
 *  @param[in] context
 *
 *  @return IPMI_CC_OK on success, an IPMI error code otherwise.
 */
ipmi_ret_t ipmi_app_watchdog_set(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                 ipmi_request_t request,
                                 ipmi_response_t response,
                                 ipmi_data_len_t data_len,
                                 ipmi_context_t context);

/** @brief The GET watchdog IPMI command.
 *  @param[in] netfn
 *  @param[in] cmd
 *  @param[in] request
 *  @param[in,out] response
 *  @param[out] data_len
 *  @param[in] context
 *
 *  @return IPMI_CC_OK on success, an IPMI error code otherwise.
 */
ipmi_ret_t ipmi_app_watchdog_get(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                 ipmi_request_t request,
                                 ipmi_response_t response,
                                 ipmi_data_len_t data_len,
                                 ipmi_context_t context);
