#include "elog-errors.hpp"
#include "error-HostEvent.hpp"
#include "sensorhandler.hpp"
#include "storagehandler.hpp"
#include "types.hpp"

#include <host-ipmid/ipmid-api.h>
#include <mapper.h>
#include <systemd/sd-bus.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <phosphor-logging/elog.hpp>
#include <vector>
#include <xyz/openbmc_project/Logging/Entry/server.hpp>

using namespace std;
using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Logging::server;
extern const ipmi::sensor::InvObjectIDMap invSensors;

//////////////////////////
struct esel_section_headers_t
{
    uint8_t sectionid[2];
    uint8_t sectionlength[2];
    uint8_t version;
    uint8_t subsectiontype;
    uint8_t compid;
};

struct severity_values_t
{
    uint8_t type;
    Entry::Level level;
};

const std::vector<severity_values_t> g_sev_desc = {
    {0x10, Entry::Level::Warning}, // recoverable error
    {0x20, Entry::Level::Warning}, // predictive error
                                   // TODO via github issue 3066 : map level
                                   // below to Level::Unrecoverable
    {0x40, Entry::Level::Error},   // unrecoverable error
                                 // TODO via github issue 3066 : map level below
                                 // to Level::Critical
    {0x50, Entry::Level::Error},   // critical error
    {0x60, Entry::Level::Error},   // error from a diagnostic test
    {0x70, Entry::Level::Warning}, // recoverable symptom
    {0xFF, Entry::Level::Error},   // unknown error
};

Entry::Level sev_lookup(uint8_t n)
{
    auto i =
        std::find_if(std::begin(g_sev_desc), std::end(g_sev_desc),
                     [n](auto p) { return p.type == n || p.type == 0xFF; });
    return i->level;
}

int find_sensor_type_string(uint8_t sensor_number, char** s)
{

    dbus_interface_t a;
    int r;

    r = find_openbmc_path(sensor_number, &a);

    if ((r < 0) || (a.bus[0] == 0))
    {
        // Just make a generic message for errors that
        // occur on sensors that don't exist
        r = asprintf(s, "Unknown Sensor (0x%02x)", sensor_number);
    }
    else
    {
        const char* p;

        if ((p = strrchr(a.path, '/')) == NULL)
        {
            p = "/Unknown Sensor";
        }

        *s = strdup(p + 1);
    }

    return 0;
}

size_t getfilestream(const char* fn, uint8_t** buffer)
{

    FILE* fp;
    ssize_t size = 0;
    int r;

    if ((fp = fopen(fn, "rb")) != NULL)
    {

        r = fseek(fp, 0, SEEK_END);
        if (r)
        {
            log<level::ERR>("Fseek failed");
            goto fclose_fp;
        }

        size = ftell(fp);
        if (size == -1L)
        {
            log<level::ERR>("Ftell failed", entry("ERROR=%s", strerror(errno)));
            size = 0;
            goto fclose_fp;
        }

        r = fseek(fp, 0, SEEK_SET);
        if (r)
        {
            log<level::ERR>("Fseek failed");
            size = 0;
            goto fclose_fp;
        }

        *buffer = new uint8_t[size];

        r = fread(*buffer, 1, size, fp);
        if (r != size)
        {
            size = 0;
            log<level::ERR>("Fread failed\n");
        }

    fclose_fp:
        fclose(fp);
    }

    return static_cast<size_t>(size);
}

Entry::Level create_esel_severity(const uint8_t* buffer)
{

    uint8_t severity;
    // Dive in to the IBM log to find the severity
    severity = (0xF0 & buffer[0x4A]);

    return sev_lookup(severity);
}

int create_esel_association(const uint8_t* buffer, std::string& inventoryPath)
{
    auto p = reinterpret_cast<const ipmi_add_sel_request_t*>(buffer);

    uint8_t sensor = p->sensornumber;

    inventoryPath = {};

    /*
     * Search the sensor number to inventory path mapping to figure out the
     * inventory associated with the ESEL.
     */
    auto found = std::find_if(invSensors.begin(), invSensors.end(),
                              [&sensor](const auto& iter) {
                                  return (iter.second.sensorID == sensor);
                              });
    if (found != invSensors.end())
    {
        inventoryPath = (*found).first;
    }

    return 0;
}

int create_esel_description(const uint8_t* buffer, Entry::Level level,
                            char** message)
{
    char* m;
    int r;

    auto p = reinterpret_cast<const ipmi_add_sel_request_t*>(buffer);

    find_sensor_type_string(p->sensornumber, &m);

    r = asprintf(message, "A %s has experienced an error of level %d", m,
                 static_cast<uint32_t>(level));
    if (r == -1)
    {
        log<level::ERR>("Failed to allocate memory for ESEL description");
    }

    free(m);

    return 0;
}

int send_esel_to_dbus(const char* desc, Entry::Level level,
                      const std::string& inventoryPath, uint8_t* debug,
                      size_t debuglen)
{

    // Allocate enough space to represent the data in hex separated by spaces,
    // to mimic how IPMI would display the data.
    unique_ptr<char[]> selData(new char[(debuglen * 3) + 1]());
    uint32_t i = 0;
    for (i = 0; i < debuglen; i++)
    {
        sprintf(&selData[i * 3], "%02x ", 0xFF & ((char*)debug)[i]);
    }
    selData[debuglen * 3] = '\0';

    using error = sdbusplus::org::open_power::Host::Error::Event;
    using metadata = org::open_power::Host::Event;

    report<error>(level, metadata::ESEL(selData.get()),
                  metadata::CALLOUT_INVENTORY_PATH(inventoryPath.c_str()));

    return 0;
}

void send_esel(uint16_t recordid)
{
    char* desc;
    uint8_t* buffer = NULL;
    const char* path = "/tmp/esel";
    ssize_t sz;
    int r;
    std::string inventoryPath;

    sz = getfilestream(path, &buffer);
    if (sz == 0)
    {
        log<level::ERR>("Error file does not exist",
                        entry("FILENAME=%s", path));
        return;
    }

    auto sev = create_esel_severity(buffer);
    create_esel_association(buffer, inventoryPath);
    create_esel_description(buffer, sev, &desc);

    r = send_esel_to_dbus(desc, sev, inventoryPath, buffer, sz);
    if (r < 0)
    {
        log<level::ERR>("Failed to send esel to dbus");
    }

    free(desc);
    delete[] buffer;

    return;
}

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

void createProcedureLogEntry(uint8_t procedureNum)
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

    using error = sdbusplus::org::open_power::Host::Error::MaintenanceProcedure;
    using metadata = org::open_power::Host::MaintenanceProcedure;

    report<error>(metadata::ESEL(data.get()),
                  metadata::PROCEDURE(static_cast<uint32_t>(procedureNum)));
}
