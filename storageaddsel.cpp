#include "elog-errors.hpp"
#include "error-HostEvent.hpp"
#include "sensorhandler.hpp"
#include "storagehandler.hpp"

#include <mapper.h>
#include <systemd/sd-bus.h>

#include <ipmid/api.hpp>
#include <ipmid/types.hpp>
#include <phosphor-logging/elog.hpp>
#include <xyz/openbmc_project/Logging/Entry/server.hpp>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <vector>

using namespace std;
using namespace phosphor::logging;
using namespace sdbusplus::server::xyz::openbmc_project::logging;

std::string readESEL(const char* fileName)
{
    std::string content;
    std::ifstream handle(fileName);

    if (handle.fail())
    {
        log<level::ERR>("Failed to open eSEL", entry("FILENAME=%s", fileName));
        return content;
    }

    handle.seekg(0, std::ios::end);
    content.resize(handle.tellg());
    handle.seekg(0, std::ios::beg);
    handle.read(&content[0], content.size());
    handle.close();

    return content;
}

void createProcedureLogEntry(uint8_t)
{
    // Read the eSEL data from the file.
    static constexpr auto eSELFile = "/tmp/esel";
    auto eSELData = readESEL(eSELFile);

    // Each byte in eSEL is formatted as %02x with a space between bytes and
    // insert '/0' at the end of the character array.
    static constexpr auto byteSeparator = 3;
    std::unique_ptr<char[]> data(
        new char[(eSELData.size() * byteSeparator) + 1]());

    for (size_t i = 0; i < eSELData.size(); i++)
    {
        sprintf(&data[i * byteSeparator], "%02x ", eSELData[i]);
    }
    data[eSELData.size() * byteSeparator] = '\0';

    /*
    TODO: This is the only failure right now.
    /usr/include/c++/13/type_traits: In instantiation of 'struct
    std::is_base_of<sdbusplus::exception::exception,
    sdbusplus::error::org::open_power::host::MaintenanceProcedure>':
    /usr/local/include/phosphor-logging/elog.hpp:191:63:   required from
    'uint32_t phosphor::logging::report(Args ...) [with T =
    sdbusplus::error::org::open_power::host::MaintenanceProcedure; Args =
    {org::open_power::host::_MaintenanceProcedure::ESEL,
    org::open_power::common::callout::_Procedure::PROCEDURE}; uint32_t =
    unsigned int]'
    ../storageaddsel.cpp:67:18:   required from here
    /usr/include/c++/13/type_traits:1411:38: error: invalid use of incomplete
    type 'struct sdbusplus::error::org::open_power::host::MaintenanceProcedure'
     1411 |     : public integral_constant<bool, __is_base_of(_Base, _Derived)>
          |                                      ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    ../elog-errors.hpp:106:8: note: forward declaration of 'struct
    sdbusplus::error::org::open_power::host::MaintenanceProcedure' 106 | struct
    MaintenanceProcedure; |        ^~~~~~~~~~~~~~~~~~~~
    /usr/local/include/phosphor-logging/elog.hpp: In instantiation of 'uint32_t
    phosphor::logging::report(Args ...) [with T =
    sdbusplus::error::org::open_power::host::MaintenanceProcedure; Args =
    {org::open_power::host::_MaintenanceProcedure::ESEL,
    org::open_power::common::callout::_Procedure::PROCEDURE}; uint32_t =
    unsigned int]':
    ../storageaddsel.cpp:67:18:   required from here
    /usr/local/include/phosphor-logging/elog.hpp:191:63: error: 'value' is not a
    member of 'std::is_base_of<sdbusplus::exception::exception,
    sdbusplus::error::org::open_power::host::MaintenanceProcedure>' 191 |
    static_assert(std::is_base_of<sdbusplus::exception_t, T>::value, | ^~~~~
    /usr/local/include/phosphor-logging/elog.hpp:201:12: error: incomplete type
    'sdbusplus::error::org::open_power::host::MaintenanceProcedure' used in
    nested name specifier 201 |         T::errDesc,
    details::deduce_entry_type<Args>{i_args}.get()...); |            ^~~~~~~
    ninja: build stopped: subcommand failed.

    */
    // using error =
    // sdbusplus::error::org::open_power::host::MaintenanceProcedure; using
    // metadata = org::open_power::host::MaintenanceProcedure;

    // report<error>(metadata::ESEL(data.get()),
    //               metadata::PROCEDURE(static_cast<uint32_t>(procedureNum)));
}
