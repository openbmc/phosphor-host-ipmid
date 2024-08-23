#pragma once

#include <sdbusplus/bus.hpp>

#include <string>
#include <tuple>

namespace settings
{

using Path = std::string;
using Service = std::string;
using Interface = std::string;

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
    Objects(sdbusplus::bus_t& bus, const std::vector<Interface>& filter);
    Objects(const Objects&) = default;
    Objects& operator=(const Objects&) = delete;
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
    std::map<Interface, std::vector<Path>> map;

    /** @brief The Dbus bus object */
    sdbusplus::bus_t& bus;
};

} // namespace settings
