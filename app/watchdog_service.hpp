#pragma once
#include <experimental/optional>
#include <sdbusplus/bus.hpp>
#include <xyz/openbmc_project/State/Watchdog/server.hpp>

/** @class WatchdogService
 *  @brief Access to the running OpenBMC watchdog implementation.
 *  @details Easy accessor for servers that implement the
 *  xyz.openbmc_project.State.Watchdog DBus API.
 */
class WatchdogService {
    public:
        WatchdogService();

        using Action = sdbusplus::xyz::openbmc_project::State::server::Watchdog::Action;

        /** @brief Contains a copy of the properties enumerated by the
         *         watchdog service.
         */
        struct Properties {
            bool initialized;
            bool enabled;
            Action expireAction;
            uint64_t interval;
            uint64_t timeRemaining;
        };

        /** @brief Retrieves a copy of the currently set properties on the
         *         host watchdog
         *
         *  @return A populated WatchdogProperties struct
         */
        Properties getProperties();

        /** @brief Sets the value of the initialized property on the host
		 *         watchdog
         *
         *  @param[in] initialized - The new initializedvalue
         */
        void setInitialized(bool initialized);

        /** @brief Sets the value of the enabled property on the host watchdog
         *
         *  @param[in] enabled - The new enabled value
         */
        void setEnabled(bool enabled);

        /** @brief Sets the value of the expireAction property on the host watchdog
         *
         *  @param[in] expireAction - The new expireAction value
         */
        void setExpireAction(Action expireAction);

        /** @brief Sets the value of the interval property on the host watchdog
         *
         *  @param[in] interval - The new interval value
         */
        void setInterval(uint64_t interval);

        /** @brief Sets the value of the timeRemaining property on the host
         *         watchdog
         *
         *  @param[in] timeRemaining - The new timeRemaining value
         */
        void setTimeRemaining(uint64_t timeRemaining);

    private:
        /** @brief sdbusplus handle */
        sdbusplus::bus::bus bus;
        /** @brief The name of the mapped host watchdog service */
        static std::experimental::optional<std::string> wd_service;

        /** @brief Sets the value of the property on the host watchdog
         *
         *  @param[in] key - The name of the property
         *  @param[in] val - The new value
         */
        template <typename T>
        void setProperty(const std::string& key, const T& val);
};
