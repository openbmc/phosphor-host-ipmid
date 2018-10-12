#include "sessions_manager.hpp"

#include "session.hpp"

#include <algorithm>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <memory>

namespace session
{

Manager::Manager()
{
    /*
     * Session ID is 0000_0000h for messages that are sent outside the session.
     * The session setup commands are sent on this session, so when the session
     * manager comes up, is creates the Session ID  0000_0000h. It is active
     * through the lifetime of the Session Manager.
     */
    sessionsMap.emplace(0, std::make_shared<Session>());
    // Seeding the pseudo-random generator
    std::srand(std::time(0));
}

std::weak_ptr<Session>
    Manager::startSession(SessionID remoteConsoleSessID, Privilege priv,
                          cipher::rakp_auth::Algorithms authAlgo,
                          cipher::integrity::Algorithms intAlgo,
                          cipher::crypt::Algorithms cryptAlgo)
{
    std::shared_ptr<Session> session = nullptr;
    SessionID sessionID = 0;
    cleanStaleEntries();
    auto activeSessions = sessionsMap.size() - MAX_SESSIONLESS_COUNT;

    if (activeSessions < MAX_SESSION_COUNT)
    {
        do
        {
            session = std::make_shared<Session>(remoteConsoleSessID, priv);

            /*
             * Every IPMI Session has two ID's attached to it Remote Console
             * Session ID and BMC Session ID. The remote console ID is passed
             * along with the Open Session request command. The BMC session ID
             * is the key for the session map and is generated using std::rand.
             * There is a rare chance for collision of BMC session ID, so the
             * following check validates that. In the case of collision the
             * created session is reset and a new session is created for
             * validating collision.
             */
            auto iterator = sessionsMap.find(session->getBMCSessionID());
            if (iterator != sessionsMap.end())
            {
                // Detected BMC Session ID collisions
                session.reset();
                continue;
            }
            else
            {
                break;
            }
        } while (1);

        // Set the Authentication Algorithm
        switch (authAlgo)
        {
            case cipher::rakp_auth::Algorithms::RAKP_HMAC_SHA1:
            {
                session->setAuthAlgo(
                    std::make_unique<cipher::rakp_auth::AlgoSHA1>(intAlgo,
                                                                  cryptAlgo));
                break;
            }
            case cipher::rakp_auth::Algorithms::RAKP_HMAC_SHA256:
            {
                session->setAuthAlgo(
                    std::make_unique<cipher::rakp_auth::AlgoSHA256>(intAlgo,
                                                                    cryptAlgo));
                break;
            }
            default:
            {
                throw std::runtime_error("Invalid Authentication Algorithm");
            }
        }
        sessionID = session->getBMCSessionID();
        sessionsMap.emplace(sessionID, std::move(session));
    }
    else
    {
        std::cerr << "E> No free sessions left: Active: " << activeSessions
                  << " Allowed: " << MAX_SESSION_COUNT << "\n";

        for (const auto& iterator : sessionsMap)
        {
            std::cerr << "E> Active Session: 0x" << std::hex
                      << std::setfill('0') << std::setw(8)
                      << (iterator.second)->getBMCSessionID() << "\n";
        }
        throw std::runtime_error("No free sessions left");
    }

    return getSession(sessionID);
}

bool Manager::stopSession(SessionID bmcSessionID)
{
    auto iter = sessionsMap.find(bmcSessionID);
    if (iter != sessionsMap.end())
    {
        iter->second->state = State::TEAR_DOWN_IN_PROGRESS;
        return true;
    }
    else
    {
        return false;
    }
}

std::weak_ptr<Session> Manager::getSession(SessionID sessionID,
                                           RetrieveOption option)
{
    switch (option)
    {
        case RetrieveOption::BMC_SESSION_ID:
        {
            auto iter = sessionsMap.find(sessionID);
            if (iter != sessionsMap.end())
            {
                return iter->second;
            }
            break;
        }
        case RetrieveOption::RC_SESSION_ID:
        {
            auto iter = std::find_if(
                sessionsMap.begin(), sessionsMap.end(),
                [sessionID](
                    const std::pair<const uint32_t, std::shared_ptr<Session>>&
                        in) -> bool {
                    return sessionID == in.second->getRCSessionID();
                });

            if (iter != sessionsMap.end())
            {
                return iter->second;
            }
            break;
        }
        default:
            throw std::runtime_error("Invalid retrieval option");
    }

    throw std::runtime_error("Session ID not found");
}

void Manager::cleanStaleEntries()
{
    for (auto iter = sessionsMap.begin(); iter != sessionsMap.end();)
    {
        auto session = iter->second;
        if ((session->getBMCSessionID() != SESSION_ZERO) &&
            !(session->isSessionActive()))
        {
            iter = sessionsMap.erase(iter);
        }
        else
        {
            ++iter;
        }
    }
}

} // namespace session
