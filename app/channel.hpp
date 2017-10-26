#include "ipmid.hpp"

/** @brief The set channel access IPMI command.
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
ipmi_ret_t ipmi_set_channel_access(ipmi_netfn_t netfn,
    ipmi_cmd_t cmd,
    ipmi_request_t request,
    ipmi_response_t response,
    ipmi_data_len_t data_len,
    ipmi_context_t context);

/** @brief The get channel access IPMI command.
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
ipmi_ret_t ipmi_get_channel_access(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
    ipmi_request_t request, ipmi_response_t response,
    ipmi_data_len_t data_len, ipmi_context_t context);

/** @brief The get channel info IPMI command.
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
ipmi_ret_t ipmi_app_channel_info(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
    ipmi_request_t request, ipmi_response_t response,
    ipmi_data_len_t data_len, ipmi_context_t context);


