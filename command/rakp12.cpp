#include "rakp12.hpp"

#include "comm_module.hpp"
#include "endian.hpp"
#include "guid.hpp"
#include "main.hpp"

#include <openssl/rand.h>

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <iostream>

namespace command
{

std::vector<uint8_t> RAKP12(const std::vector<uint8_t>& inPayload,
                            const message::Handler& handler)
{
    std::vector<uint8_t> outPayload(sizeof(RAKP2response));
    auto request = reinterpret_cast<const RAKP1request*>(inPayload.data());
    auto response = reinterpret_cast<RAKP2response*>(outPayload.data());

    // Session ID zero is reserved for Session Setup
    if (endian::from_ipmi(request->managedSystemSessionID) ==
        session::SESSION_ZERO)
    {
        std::cerr << "RAKP12: BMC invalid Session ID\n";
        response->rmcpStatusCode =
            static_cast<uint8_t>(RAKP_ReturnCode::INVALID_SESSION_ID);
        return outPayload;
    }

    std::shared_ptr<session::Session> session;
    try
    {
        session =
            std::get<session::Manager&>(singletonPool)
                .getSession(endian::from_ipmi(request->managedSystemSessionID));
    }
    catch (std::exception& e)
    {
        std::cerr << e.what() << "\n";
        response->rmcpStatusCode =
            static_cast<uint8_t>(RAKP_ReturnCode::INVALID_SESSION_ID);
        return outPayload;
    }

    auto rakp1Size =
        sizeof(RAKP1request) - (userNameMaxLen - request->user_name_len);

    // Validate user name length in the message
    if (request->user_name_len > userNameMaxLen ||
        inPayload.size() != rakp1Size)
    {
        response->rmcpStatusCode =
            static_cast<uint8_t>(RAKP_ReturnCode::INVALID_NAME_LENGTH);
        return outPayload;
    }

    session->userName.assign(request->user_name, request->user_name_len);

    // Validate the user name if the username is provided
    if (request->user_name_len &&
        (session->userName != cipher::rakp_auth::userName))
    {
        response->rmcpStatusCode =
            static_cast<uint8_t>(RAKP_ReturnCode::UNAUTH_NAME);
        return outPayload;
    }

    // Update transaction time
    session->updateLastTransactionTime();

    auto rcSessionID = endian::to_ipmi(session->getRCSessionID());
    auto bmcSessionID = endian::to_ipmi(session->getBMCSessionID());
    auto authAlgo = session->getAuthAlgo();

    /*
     * Generate Key Authentication Code - RAKP 2
     *
     * 1) Remote Console Session ID - 4 bytes
     * 2) Managed System Session ID - 4 bytes
     * 3) Remote Console Random Number - 16 bytes
     * 4) Managed System Random Number - 16 bytes
     * 5) Managed System GUID - 16 bytes
     * 6) Requested Privilege Level - 1 byte
     * 7) User Name Length Byte - 1 byte (0 for 'null' username)
     * 8) User Name - variable (absent for 'null' username)
     */

    std::vector<uint8_t> input;
    input.resize(sizeof(rcSessionID) + sizeof(bmcSessionID) +
                 cipher::rakp_auth::REMOTE_CONSOLE_RANDOM_NUMBER_LEN +
                 cipher::rakp_auth::BMC_RANDOM_NUMBER_LEN + BMC_GUID_LEN +
                 sizeof(request->req_max_privilege_level) +
                 sizeof(request->user_name_len) + session->userName.size());

    auto iter = input.begin();

    // Remote Console Session ID
    std::copy_n(reinterpret_cast<uint8_t*>(&rcSessionID), sizeof(rcSessionID),
                iter);
    std::advance(iter, sizeof(rcSessionID));

    // Managed System Session ID
    std::copy_n(reinterpret_cast<uint8_t*>(&bmcSessionID), sizeof(bmcSessionID),
                iter);
    std::advance(iter, sizeof(bmcSessionID));

    // Copy the Remote Console Random Number from the RAKP1 request to the
    // Authentication Algorithm
    std::copy_n(
        reinterpret_cast<const uint8_t*>(request->remote_console_random_number),
        cipher::rakp_auth::REMOTE_CONSOLE_RANDOM_NUMBER_LEN,
        authAlgo->rcRandomNum.begin());

    std::copy(authAlgo->rcRandomNum.begin(), authAlgo->rcRandomNum.end(), iter);
    std::advance(iter, cipher::rakp_auth::REMOTE_CONSOLE_RANDOM_NUMBER_LEN);

    // Generate the Managed System Random Number
    if (!RAND_bytes(input.data() + sizeof(rcSessionID) + sizeof(bmcSessionID) +
                        cipher::rakp_auth::REMOTE_CONSOLE_RANDOM_NUMBER_LEN,
                    cipher::rakp_auth::BMC_RANDOM_NUMBER_LEN))
    {
        response->rmcpStatusCode =
            static_cast<uint8_t>(RAKP_ReturnCode::INSUFFICIENT_RESOURCE);
        return outPayload;
    }

    // Copy the Managed System Random Number to the Authentication Algorithm
    std::copy_n(iter, cipher::rakp_auth::BMC_RANDOM_NUMBER_LEN,
                authAlgo->bmcRandomNum.begin());
    std::advance(iter, cipher::rakp_auth::BMC_RANDOM_NUMBER_LEN);

    // Managed System GUID
    std::copy_n(cache::guid.data(), cache::guid.size(), iter);
    std::advance(iter, BMC_GUID_LEN);

    // Requested Privilege Level
    session->curPrivLevel =
        static_cast<session::Privilege>(request->req_max_privilege_level);
    std::copy_n(&(request->req_max_privilege_level),
                sizeof(request->req_max_privilege_level), iter);
    std::advance(iter, sizeof(request->req_max_privilege_level));

    // Set Max Privilege to ADMIN
    session->maxPrivLevel = session::Privilege::ADMIN;

    // User Name Length Byte
    std::copy_n(&(request->user_name_len), sizeof(request->user_name_len),
                iter);
    std::advance(iter, sizeof(request->user_name_len));

    std::copy_n(session->userName.data(), session->userName.size(), iter);

    // Generate Key Exchange Authentication Code - RAKP2
    auto output = authAlgo->generateHMAC(input);

    response->messageTag = request->messageTag;
    response->rmcpStatusCode = static_cast<uint8_t>(RAKP_ReturnCode::NO_ERROR);
    response->reserved = 0;
    response->remoteConsoleSessionID = rcSessionID;

    // Copy Managed System Random Number to the Response
    std::copy(authAlgo->bmcRandomNum.begin(), authAlgo->bmcRandomNum.end(),
              response->managed_system_random_number);

    // Copy System GUID to the Response
    std::copy_n(cache::guid.data(), cache::guid.size(),
                response->managed_system_guid);

    // Insert the HMAC output into the payload
    outPayload.insert(outPayload.end(), output.begin(), output.end());
    return outPayload;
}

} // namespace command
