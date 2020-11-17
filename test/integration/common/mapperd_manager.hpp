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

class MapperxDaemon : public Daemon
{
  public:
    MapperxDaemon(const MapperxDaemon&) = delete;
    MapperxDaemon& operator=(const MapperxDaemon&) = delete;
    MapperxDaemon(MapperxDaemon&&) = delete;
    MapperxDaemon& operator=(MapperxDaemon&&) = delete;

    MapperxDaemon(const char* mapperxPath = "mapperx",
                  const char* serviceNamespaces = "xyz.openbmc_project");

    std::string getPathNotFoundHelpMsg() override;

  private:
    static constexpr char serviceNamespacesArg[] = "--service-namespaces";
};

} // namespace integration
} // namespace test
} // namespace openbmc
