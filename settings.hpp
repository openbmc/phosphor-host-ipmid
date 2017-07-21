#pragma once

#include <string>
#include <utility>
#include <sdbusplus/bus.hpp>

namespace settings
{

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

        using Interface = std::string;
        using Path = std::string;
        using Service = std::string;

        /** @brief map of settings objects */
        std::map<Interface, std::pair<Path, Service>> map;
};

} // namespace settings
