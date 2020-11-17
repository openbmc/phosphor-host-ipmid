#pragma once

#include <sdbusplus/test/integration/daemon_manager.hpp>
#include <string>

using sdbusplus::test::integration::Daemon;

namespace openbmc
{

namespace test
{

namespace integration
{

/** This class is responsible for managing the OpenBMC mapperx daemon
 * specifically.
 *
 * It also prints a help message to guide the user if mapperx was not found.
 */
class MapperxDaemon : public Daemon
{
  public:
    MapperxDaemon(const MapperxDaemon&) = delete;
    MapperxDaemon& operator=(const MapperxDaemon&) = delete;
    MapperxDaemon(MapperxDaemon&&) = delete;
    MapperxDaemon& operator=(MapperxDaemon&&) = delete;

    /** Constructs the daemon manager for mapperx.
     *
     * @param mapperxPath - the path to the executable file for running mapperx.
     * @param serviceNamespaces - the service namespace arg to pass to mapperx.
     */
    MapperxDaemon(std::string mapperxPath = "mapperx",
                  std::string serviceNamespaces = "xyz.openbmc_project");

    std::string getPathNotFoundHelpMsg() override;

  private:
    static constexpr char serviceNamespacesArg[] = "--service-namespaces";
};

} // namespace integration
} // namespace test
} // namespace openbmc
