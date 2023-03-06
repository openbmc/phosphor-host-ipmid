#include "sessions_manager.hpp"

#include "main.hpp"
#include "session.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <user_channel/channel_layer.hpp>

#include <algorithm>
#include <cstdlib>
#include <iomanip>
#include <memory>

namespace session
{

static std::array<uint8_t, session::maxNetworkInstanceSupported>
    ipmiNetworkChannelNumList = {0};

void Manager::setNetworkInstance(void)
{
    uint8_t index = 0, ch = 1;
    // Constructing net-ipmid instances list based on channel info
    // valid channel start from 1 to 15  and assuming max 4 LAN channel
    // supported

    while (ch < ipmi::maxIpmiChannels &&
           index < session::maxNetworkInstanceSupported)
    {
        ipmi::ChannelInfo chInfo;
        ipmi::getChannelInfo(ch, chInfo);
        if (static_cast<ipmi::EChannelMediumType>(chInfo.mediumType) ==
            ipmi::EChannelMediumType::lan8032)
        {
            if (getInterfaceIndex() == ch)
            {
                ipmiNetworkInstance = index;
            }

            ipmiNetworkChannelNumList[index] = ch;
            index++;
        }
        ch++;
    }
}

uint8_t Manager::getNetworkInstance(void)
{
    return ipmiNetworkInstance;
}

void Manager::managerInit(const std::string& channel)
{
    /*
     * Session ID is 0000_0000h for messages that are sent outside the session.
     * The session setup commands are sent on this session, so when the session
     * manager comes up, is creates the Session ID  0000_0000h. It is active
     * through the lifetime of the Session Manager.
     */

    objManager = std::make_unique<sdbusplus::server::manager_t>(
        *getSdBus(), session::sessionManagerRootPath);

    auto objPath =
        std::string(session::sessionManagerRootPath) + "/" + channel + "/0";

    chName = channel;
    setNetworkInstance();
    sessionsMap.emplace(
        0, std::make_shared<Session>(*getSdBus(), objPath.c_str(), 0, 0, 0));

    // set up the timer for clearing out stale sessions
    scheduleSessionCleaner(std::chrono::microseconds(3 * 1000 * 1000));
}

std::shared_ptr<Session>
    Manager::startSession(SessionID remoteConsoleSessID, Privilege priv,
                          cipher::rakp_auth::Algorithms authAlgo,
                          cipher::integrity::Algorithms intAlgo,
                          cipher::crypt::Algorithms cryptAlgo)
{
    std::shared_ptr<Session> session = nullptr;
    SessionID bmcSessionID = 0;
    cleanStaleEntries();
    // set up the timer for monitoring this session
    scheduleSessionCleaner(std::chrono::microseconds(1 * 1000 * 1000));

    uint8_t sessionHandle = 0;

    auto activeSessions = sessionsMap.size() - session::maxSessionlessCount;

    if (activeSessions < maxSessionHandles)
    {
        do
        {
            bmcSessionID = (crypto::prng::rand());
            bmcSessionID &= session::multiIntfaceSessionIDMask;
            // In sessionID , BIT 31 BIT30 are used for netipmid instance
            bmcSessionID |= static_cast<uint32_t>(ipmiNetworkInstance) << 30;
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
            auto iterator = sessionsMap.find(bmcSessionID);
            if (iterator != sessionsMap.end())
            {
                // Detected BMC Session ID collisions
                continue;
            }
            else
            {
                break;
            }
        } while (1);

        sessionHandle = storeSessionHandle(bmcSessionID);

        if (!sessionHandle)
        {
            throw std::runtime_error(
                "Invalid sessionHandle - No sessionID slot ");
        }
        sessionHandle &= session::multiIntfaceSessionHandleMask;
        // In sessionID , BIT 31 BIT30 are used for netipmid instance
        sessionHandle |= static_cast<uint8_t>(ipmiNetworkInstance) << 6;
        std::stringstream sstream;
        sstream << std::hex << bmcSessionID;
        std::stringstream shstream;
        shstream << std::hex << (int)sessionHandle;
        auto objPath = std::string(session::sessionManagerRootPath) + "/" +
                       chName + "/" + sstream.str() + "_" + shstream.str();
        session = std::make_shared<Session>(*getSdBus(), objPath.c_str(),
                                            remoteConsoleSessID, bmcSessionID,
                                            static_cast<uint8_t>(priv));

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

        sessionsMap.emplace(bmcSessionID, session);
        session->sessionHandle(sessionHandle);

        return session;
    }

    lg2::info("No free RMCP+ sessions left");

    throw std::runtime_error("No free sessions left");
}

bool Manager::stopSession(SessionID bmcSessionID)
{
    auto iter = sessionsMap.find(bmcSessionID);
    if (iter != sessionsMap.end())
    {
        iter->second->state(
            static_cast<uint8_t>(session::State::tearDownInProgress));
        return true;
    }
    else
    {
        return false;
    }
}

std::shared_ptr<Session> Manager::getSession(SessionID sessionID,
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
    // with overflow = min(1, max - active sessions)
    // active idle time in seconds = 60 / overflow^3
    constexpr int baseIdleMicros = 60 * 1000 * 1000;
    // no +1 for the zero session here because this is just active sessions
    int sessionDivisor =
        getActiveSessionCount() - session::maxSessionCountPerChannel;
    sessionDivisor = std::max(0, sessionDivisor) + 1;
    sessionDivisor = sessionDivisor * sessionDivisor * sessionDivisor;
    int activeMicros = baseIdleMicros / sessionDivisor;

    // with overflow = min(1, max - total sessions)
    // setup idle time in seconds = max(3, 60 / overflow^3)

    // +1 for the zero session here because size() counts that too
    int setupDivisor =
        sessionsMap.size() - (session::maxSessionCountPerChannel + 1);
    setupDivisor = std::max(0, setupDivisor) + 1;
    setupDivisor = setupDivisor * setupDivisor * setupDivisor;
    constexpr int maxSetupMicros = 3 * 1000 * 1000;
    int setupMicros = std::min(maxSetupMicros, baseIdleMicros / setupDivisor);

    std::chrono::microseconds activeGrace(activeMicros);
    std::chrono::microseconds setupGrace(setupMicros);

    for (auto iter = sessionsMap.begin(); iter != sessionsMap.end();)
    {
        auto session = iter->second;
        // special handling for sessionZero
        if (session->getBMCSessionID() == session::sessionZero)
        {
            iter++;
            continue;
        }
        if (!(session->isSessionActive(activeGrace, setupGrace)))
        {
            lg2::info(
                "Removing idle IPMI LAN session, id: {ID}, handler: {HANDLE}",
                "ID", session->getBMCSessionID(), "HANDLE",
                getSessionHandle(session->getBMCSessionID()));
            sessionHandleMap[getSessionHandle(session->getBMCSessionID())] = 0;
            iter = sessionsMap.erase(iter);
        }
        else
        {
            iter++;
        }
    }
    if (sessionsMap.size() > 1)
    {
        constexpr int maxCleanupDelay = 1 * 1000 * 1000;
        std::chrono::microseconds cleanupDelay(
            std::min(setupMicros, maxCleanupDelay));
        scheduleSessionCleaner(cleanupDelay);
    }
}

uint8_t Manager::storeSessionHandle(SessionID bmcSessionID)
{
    // Handler index 0 is  reserved for invalid session.
    // index starts with 1, for direct usage. Index 0 reserved
    for (size_t i = 1; i < session::maxSessionHandles; i++)
    {
        if (sessionHandleMap[i] == 0)
        {
            sessionHandleMap[i] = bmcSessionID;
            return i;
        }
    }
    return 0;
}

uint32_t Manager::getSessionIDbyHandle(uint8_t sessionHandle) const
{
    if (sessionHandle < session::maxSessionHandles)
    {
        return sessionHandleMap[sessionHandle];
    }
    return 0;
}

uint8_t Manager::getSessionHandle(SessionID bmcSessionID) const
{
    // Handler index 0 is reserved for invalid session.
    // index starts with 1, for direct usage. Index 0 reserved
    for (size_t i = 1; i < session::maxSessionHandles; i++)
    {
        if (sessionHandleMap[i] == bmcSessionID)
        {
            return (i);
        }
    }
    return 0;
}
uint8_t Manager::getActiveSessionCount() const
{
    return (std::count_if(
        sessionsMap.begin(), sessionsMap.end(),
        [](const std::pair<const uint32_t, std::shared_ptr<Session>>& in)
            -> bool {
            return in.second->state() ==
                   static_cast<uint8_t>(session::State::active);
        }));
}

void Manager::scheduleSessionCleaner(const std::chrono::microseconds& when)
{
    std::chrono::duration expTime =
        timer.expiry() - boost::asio::steady_timer::clock_type::now();
    if (expTime > std::chrono::microseconds(0) && expTime < when)
    {
        // if timer has not already expired AND requested timeout is greater
        // than current timeout then ignore this new requested timeout
        return;
    }
    timer.expires_after(when);
    timer.async_wait([this](const boost::system::error_code& ec) {
        if (!ec)
        {
            cleanStaleEntries();
        }
    });
}

} // namespace session
