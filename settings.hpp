#pragma once

#include <string>
#include <sdbusplus/bus.hpp>

namespace settings
{

using Path = std::string;
using Service = std::string;
using Interface = std::string;

constexpr auto root = "/";

/** @class Objects
 *  @brief Fetch paths of settings d-bus objects of interest, upon construction
 */
struct Objects
{
    public:
        /** @brief Constructor - fetch settings objects
         *
         * @param[in] bus - The Dbus bus object
         * @param[in] filter - A vector of settings interfaces the caller is
         *            interested in.
         */
        Objects(sdbusplus::bus::bus& bus, const std::vector<Interface>& filter);
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

        // TODO openbmc/openbmc#2058 - This will break when multiple settings,
        // or in general multiple objects implement a single setting interface.
        // For instance this will break for a 2-blade server, because we'd have
        // 2 sets of settings objects. Need to revisit and fix this.
        /** @brief map of settings objects */
        std::map<Interface, Path> map;

        /** @brief The Dbus bus object */
        sdbusplus::bus::bus& bus;
};

} // namespace settings
