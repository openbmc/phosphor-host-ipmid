#include "provider_registration.hpp"

#include "command_table.hpp"
#include "main.hpp"

#include <dirent.h>
#include <dlfcn.h>
#include <ipmid/api.h>
#include <stdlib.h>
#include <string.h>

#include <phosphor-logging/log.hpp>

using namespace phosphor::logging;

namespace provider
{

int handler_select(const struct dirent* entry)
{
    // Check for versioned libraries .so.*
    if (strstr(entry->d_name, PROVIDER_SONAME_EXTN))
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

void registerCallbackHandlers(const char* providerLibPath)
{
    if (providerLibPath == NULL)
    {
        log<level::ERR>(
            "Path not provided for registering IPMI provider libraries");
        return;
    }

    struct dirent** handlerList = nullptr;
    std::string handlerPath(providerLibPath);

    auto numLibs =
        scandir(providerLibPath, &handlerList, handler_select, alphasort);
    if (numLibs < 0)
    {
        return;
    }

    // dlopen each IPMI provider shared library
    while (numLibs--)
    {
        handlerPath = providerLibPath;
        handlerPath += handlerList[numLibs]->d_name;

        auto lib_handler = dlopen(handlerPath.c_str(), RTLD_NOW);

        if (lib_handler == NULL)
        {
            log<level::ERR>("Error opening provider library",
                            entry("PATH=%s", handlerPath.c_str()),
                            entry("ERROR=%s", dlerror()));
        }
        free(handlerList[numLibs]);
    }

    free(handlerList);
}

} // namespace provider

/*
 * @brief Method that gets called from IPMI provider shared libraries to get
 *        the command handlers registered.
 *
 * When the IPMI provider shared library is loaded, the dynamic loader program
 * looks for special section(.ctors on ELF) which contains references to the
 * functions marked with the constructor attributes. This function is invoked
 * in such manner.
 *
 * @param[in] netfn - Network Function code
 * @param[in] cmd - Command
 * @param[in] context - User specific data
 * @param[in] handler - The callback routine for the command
 * @param[in] priv - IPMI Command Privilege
 */
void ipmi_register_callback(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                            ipmi_context_t context, ipmid_callback_t handler,
                            ipmi_cmd_privilege_t priv)
{
    uint16_t netFn = netfn << 10;

    // The payload type of IPMI commands provided by the shared libraries
    // is IPMI
    command::CommandID command = {
        ((static_cast<uint32_t>(message::PayloadType::IPMI)) << 16) | netFn |
        cmd};

    std::get<command::Table&>(singletonPool)
        .registerCommand(command, std::make_unique<command::ProviderIpmidEntry>(
                                      command, handler,
                                      static_cast<session::Privilege>(priv)));
}
