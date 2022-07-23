#pragma once

#include "main.hpp"
#include "session.hpp"

#include <boost/asio/steady_timer.hpp>
#include <ipmid/api.hpp>
#include <ipmid/sessiondef.hpp>

#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <string>

namespace session
{

enum class RetrieveOption
{
    BMC_SESSION_ID,
    RC_SESSION_ID,
};

static constexpr size_t maxSessionHandles = multiIntfaceSessionHandleMask;

/**
 * @class Manager
 *
 * Manager class acts a manager for the IPMI sessions and provides interfaces
 * to start a session, stop a session and get reference to the session objects.
 *
 */

class Manager
{
  private:
    struct Private
    {};

  public:
    // BMC Session ID is the key for the map
    using SessionMap = std::map<SessionID, std::shared_ptr<Session>>;

    Manager() = delete;
    Manager(std::shared_ptr<boost::asio::io_context>& io, const Private&) :
        io(io), timer(*io){};
    ~Manager() = default;
    Manager(const Manager&) = delete;
    Manager& operator=(const Manager&) = delete;
    Manager(Manager&&) = default;
    Manager& operator=(Manager&&) = default;

    /**
     * @brief Get a reference to the singleton Manager
     *
     * @return Manager reference
     */
    static Manager& get()
    {
        static std::shared_ptr<Manager> ptr = nullptr;
        if (!ptr)
        {
            std::shared_ptr<boost::asio::io_context> io = getIo();
            ptr = std::make_shared<Manager>(io, Private());
            if (!ptr)
            {
                throw std::runtime_error("failed to create session manager");
            }
        }
        return *ptr;
    }

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
    std::shared_ptr<Session>
        startSession(SessionID remoteConsoleSessID, Privilege priv,
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
    std::shared_ptr<Session>
        getSession(SessionID sessionID,
                   RetrieveOption option = RetrieveOption::BMC_SESSION_ID);
    uint8_t getActiveSessionCount() const;
    uint8_t getSessionHandle(SessionID bmcSessionID) const;
    uint8_t storeSessionHandle(SessionID bmcSessionID);
    uint32_t getSessionIDbyHandle(uint8_t sessionHandle) const;

    void managerInit(const std::string& channel);

    uint8_t getNetworkInstance(void);

    /**
     * @brief Clean Session Stale Entries
     *
     *  Schedules cleaning the inactive sessions entries from the Session Map
     */
    void scheduleSessionCleaner(const std::chrono::microseconds& grace);

  private:
    /**
     * @brief reclaim system resources by limiting idle sessions
     *
     * Limits on active, authenticated sessions are calculated independently
     * from in-setup sessions, which are not required to be authenticated. This
     * will prevent would-be DoS attacks by calling a bunch of Open Session
     * requests to fill up all available sessions. Too many active sessions will
     * trigger a shorter timeout, but is unaffected by setup session counts.
     *
     * For active sessions, grace time is inversely proportional to (the number
     * of active sessions beyond max sessions per channel)^3
     *
     * For sessions in setup, grace time is inversely proportional to (the
     * number of total sessions beyond max sessions per channel)^3, with a max
     * of 3 seconds
     */
    void cleanStaleEntries();

    std::shared_ptr<boost::asio::io_context> io;
    boost::asio::steady_timer timer;

    std::array<uint32_t, session::maxSessionHandles> sessionHandleMap = {0};

    /**
     * @brief Session Manager keeps the session objects as a sorted
     *        associative container with Session ID as the unique key
     */
    SessionMap sessionsMap;
    std::unique_ptr<sdbusplus::server::manager_t> objManager = nullptr;
    std::string chName{}; // Channel Name
    uint8_t ipmiNetworkInstance = 0;
    void setNetworkInstance(void);
};

} // namespace session
