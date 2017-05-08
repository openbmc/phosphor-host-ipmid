#pragma once

namespace provider
{

/**
 * @brief Provider Library filename extension
 *
 * Autotools versions the shared libraries, so the shared libraries end with
 * extension name .so.*
 */

constexpr auto PROVIDER_SONAME_EXTN = ".so.";

/**
 * @brief Register Callback handlers for IPMI provider libraries
 *
 * Open the directory path for net-ipmid provider libraries and scan the
 * directory for files that end with .so.*. and dlopen the shared libraries
 * to register the handlers for the callback routines.
 *
 * @param[in] providerLibPath - Directory path for reading the IPMI provider
 *                              libraries
 */
void registerCallbackHandlers(const char* providerLibPath);

} // namespace provider
