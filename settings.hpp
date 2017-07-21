#pragma once

#include <string>
#include <sdbusplus/bus.hpp>

namespace settings
{

using Path = std::string;
using Service = std::string;
using Interface = std::string;

constexpr auto root = "/";
constexpr auto bootModeIntf =
    "xyz.openbmc_project.Control.Boot.Mode";
constexpr auto bootSourceIntf =
    "xyz.openbmc_project.Control.Boot.Source";
constexpr auto restrictionModeIntf =
    "xyz.openbmc_project.Control.Security.RestrictionMode";
constexpr auto powerRestoreIntf =
    "xyz.openbmc_project.Control.Power.RestorePolicy";

/** @class Objects
 *  @brief Fetch paths of settings d-bus objects of interest, upon construction
 */
struct Objects
{
    public:
        /** @brief Constructor - fetch settings objects
         *
         * @param[in] bus - The Dbus bus object
         */
        Objects(sdbusplus::bus::bus& bus);
        Objects(const Objects&) = default;
        Objects& operator=(const Objects&) = default;
        Objects(Objects&&) = delete;
        Objects& operator=(Objects&&) = delete;
        ~Objects() = default;

        /** @brief Fetch d-bus service, given a path and an interface. The
         *         service can't be cached because mapper returns unique
         *         service names.
         *
         * @param[in] path - The Dbus object
         * @param[in] interface - The Dbus interface
         *
         * @return std::string - the dbus service
         */
        Service service(const Path& path, const Interface& interface) const;

        /** @brief map of settings objects */
        std::map<Interface, Path> map;

        /** @brief The Dbus bus object */
        sdbusplus::bus::bus& bus;
};

} // namespace settings
