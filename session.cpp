#include "session.hpp"

#include <ctime>

#include "endian.hpp"

namespace session
{

bool Session::isSessionActive()
{
    auto currentTime = std::chrono::steady_clock::now();
    auto elapsedSeconds = std::chrono::duration_cast<std::chrono::seconds>
                          (currentTime - lastTime);

    switch (state)
    {
        case State::SETUP_IN_PROGRESS:
            if (elapsedSeconds < SESSION_SETUP_TIMEOUT)
            {
                return true;
            }
        case State::ACTIVE:
            if (elapsedSeconds < SESSION_INACTIVITY_TIMEOUT)
            {
                return true;
            }
        default:
            return false;
    }
}

} // namespace session
