#include "common/mapperd_manager.hpp"

#include <sdbusplus/test/integration/daemon_manager.hpp>
#include <string>
#include <vector>

using sdbusplus::test::integration::Daemon;

namespace openbmc
{

namespace test
{

namespace integration
{

MapperxDaemon::MapperxDaemon(std::string mapperxPath,
                             std::string serviceNamespaces) :
    Daemon(std::vector<std::string>(
        {mapperxPath, serviceNamespacesArg, serviceNamespaces}))
{
}

std::string MapperxDaemon::getPathNotFoundHelpMsg()
{
    return getExecutionPath() + R"( is required for running the test.
        It is available at https://github.com/openbmc/phosphor-objmgr.
        Make sure the executable is available on system path.)";
}

} // namespace integration
} // namespace test
} // namespace openbmc
