#pragma once

#include "session.hpp"

#include <map>
#include <memory>
#include <mutex>

namespace session
{

enum class RetrieveOption
{
    BMC_SESSION_ID,
    RC_SESSION_ID,
};

constexpr size_t SESSION_ZERO = 0;
constexpr size_t MAX_SESSIONLESS_COUNT = 1;
constexpr size_t MAX_SESSION_COUNT = 5;

/**
 * @class Manager
 *
 * Manager class acts a manager for the IPMI sessions and provides interfaces
 * to start a session, stop a session and get reference to the session objects.
 *
 */

class Manager
{
  public:
    // BMC Session ID is the key for the map
    using SessionMap = std::map<SessionID, std::shared_ptr<Session>>;

    Manager();
    ~Manager() = default;
    Manager(const Manager&) = delete;
    Manager& operator=(const Manager&) = delete;
    Manager(Manager&&) = default;
    Manager& operator=(Manager&&) = default;

    /**
     * @brief Start an IPMI session
     *
     * @param[in] remoteConsoleSessID - Remote Console Session ID mentioned
     *            in the Open SessionRequest Command
     * @param[in] priv - Privilege level requested
     * @param[in] authAlgo - Authentication Algorithm
     * @param[in] intAlgo - Integrity Algorithm
     * @param[in] cryptAlgo - Confidentiality Algorithm
     *
     * @return session handle on success and nullptr on failure
     *
     */
    std::weak_ptr<Session> startSession(SessionID remoteConsoleSessID,
                                        Privilege priv,
                                        cipher::rakp_auth::Algorithms authAlgo,
                                        cipher::integrity::Algorithms intAlgo,
                                        cipher::crypt::Algorithms cryptAlgo);

    /**
     * @brief Stop IPMI Session
     *
     * @param[in] bmcSessionID - BMC Session ID
     *
     * @return true on success and failure if session ID is invalid
     *
     */
    bool stopSession(SessionID bmcSessionID);

    /**
     * @brief Get Session Handle
     *
     * @param[in] sessionID - Session ID
     * @param[in] option - Select between BMC Session ID and Remote Console
     *            Session ID, Default option is BMC Session ID
     *
     * @return session handle on success and nullptr on failure
     *
     */
    std::weak_ptr<Session>
        getSession(SessionID sessionID,
                   RetrieveOption option = RetrieveOption::BMC_SESSION_ID);

  private:
    /**
     * @brief Session Manager keeps the session objects as a sorted
     *        associative container with Session ID as the unique key
     */
    SessionMap sessionsMap;

    /**
     * @brief Clean Session Stale Entries
     *
     *  Removes the inactive sessions entries from the Session Map
     */
    void cleanStaleEntries();
};

} // namespace session
