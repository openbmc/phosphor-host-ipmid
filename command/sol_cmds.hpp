#pragma once

#include <vector>
#include "message_handler.hpp"

namespace sol
{

namespace command
{

/** @brief SOL Payload Handler
 *
 *  This command is used for activating and deactivating a payload type under a
 *  given IPMI session. The UDP Port number for SOL is the same as the port that
 *  was used to establish the IPMI session.
 *
 *  @param[in] inPayload - Request data for the command.
 *  @param[in] handler - Reference to the message handler.
 *
 *  @return Response data for the command.
 */
std::vector<uint8_t> payloadHandler(std::vector<uint8_t>& inPayload,
                                    const message::Handler& handler);
} // namespace command

} // namespace sol
