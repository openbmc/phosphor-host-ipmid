#include <stdint.h>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <vector>
#include <memory>
#include <systemd/sd-bus.h>
#include <mapper.h>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/elog-errors-HostEvent.hpp>
#include "host-ipmid/ipmid-api.h"
#include "sensorhandler.h"
#include "storagehandler.h"


using namespace std;
using namespace phosphor::logging;

//////////////////////////
struct esel_section_headers_t {
	uint8_t sectionid[2];
	uint8_t sectionlength[2];
	uint8_t version;
	uint8_t subsectiontype;
	uint8_t compid;
};

struct severity_values_t {
	uint8_t type;
	const char *description;
};


const std::vector<severity_values_t> g_sev_desc = {
	{0x10, "recoverable error"},
	{0x20, "predictive error"},
	{0x40, "unrecoverable error"},
	{0x50, "critical error"},
	{0x60, "error from a diagnostic test"},
	{0x70, "recovered symptom "},
	{0xFF, "Unknown"},
};

const char* sev_lookup(uint8_t n) {
	auto i = std::find_if(std::begin(g_sev_desc), std::end(g_sev_desc),
	                      [n](auto p){ return p.type == n || p.type == 0xFF; });
	return i->description;
}




int find_sensor_type_string(uint8_t sensor_number, char **s) {

	dbus_interface_t a;
	const char *p;
	int r;

	r = find_openbmc_path("SENSOR", sensor_number, &a);

	if ((r < 0) || (a.bus[0] == 0)) {
		// Just make a generic message for errors that
		// occur on sensors that dont exist
		r = asprintf(s, "Unknown Sensor (0x%02x)", sensor_number);
	} else {

		if ((p = strrchr (a.path, '/')) == NULL) {
			p = "/Unknown Sensor";
		}

		*s = strdup(p+1);
	}

	return 0;
}


size_t getfilestream(const char *fn, uint8_t **buffer) {

	FILE *fp;
	ssize_t size = 0;
	int r;

	if ((fp = fopen(fn, "rb")) != NULL) {

		r = fseek(fp, 0, SEEK_END);
		if (r) {
			fprintf(stderr,"Fseek failed\n");
			goto fclose_fp;
		}

		size = ftell(fp);
		if (size == -1L) {
			fprintf(stderr,"Ftell failed for %s\n", strerror(errno));
			size = 0;
			goto fclose_fp;
		}

		r = fseek(fp, 0, SEEK_SET);
		if (r) {
			fprintf(stderr,"Fseek failed\n");
			size = 0;
			goto fclose_fp;
		}

		*buffer = new uint8_t [size];

		r = fread(*buffer, 1, size, fp);
		if ( r != size) {
			size = 0;
			fprintf(stderr,"Fread failed\n");
		}

fclose_fp:
		fclose(fp);
	}

	return static_cast<size_t>(size);
}


const char *create_esel_severity(const uint8_t *buffer) {

	uint8_t severity;
	// Dive in to the IBM log to find the severity
	severity = (0xF0  & buffer[0x4A]);

	return sev_lookup(severity);
}

int create_esel_association(const uint8_t *buffer, char **m) {

	ipmi_add_sel_request_t *p;
	dbus_interface_t dbusint;
	uint8_t sensor;

	p = ( ipmi_add_sel_request_t *) buffer;

	sensor = p->sensornumber;

	find_openbmc_path("SENSOR", sensor, &dbusint);

	// Simply no associations if the sensor can not be found
	if (strlen(dbusint.path) < 1) {
		printf("Sensor 0x%x not found\n", sensor);
		memset(dbusint.path,0,sizeof(dbusint.path));
	}

	*m = strdup(dbusint.path);

	return 0;
}



int create_esel_description(const uint8_t *buffer, const char *sev, char **message) {


	ipmi_add_sel_request_t *p;
	char *m;
	int r;

	p =  ( ipmi_add_sel_request_t *) buffer;

	find_sensor_type_string(p->sensornumber,&m);

	r = asprintf(message, "A %s has experienced a %s", m, sev );
	if (r == -1) {
		fprintf(stderr,
			"Failed to allocate memory for ESEL description\n");
	}

	free(m);

	return 0;
}


int send_esel_to_dbus(const char *desc, const char *sev, const char *details, uint8_t *debug, size_t debuglen) {

    // Allocate enough space to represent the data in hex separated by spaces,
    // to mimic how IPMI would display the data.
    unique_ptr<char[]> selData(new char[(debuglen*3) + 1]());
    uint32_t i = 0;
    for(i = 0; i < debuglen; i++)
    {
        sprintf(&selData[i*3], "%02x ", 0xFF & ((char*)debug)[i]);
    }
    selData[debuglen*3] = '\0';

    log<level::INFO>("Received Host Event", entry("ESEL=%s", selData.get()));

    try
    {
        elog<org::open_power::Error::Host::Event>(
            prev_entry<org::open_power::Error::Host::Event::ESEL>());
    }
    catch (org::open_power::Error::Host::Event& e)
    {
        commit(org::open_power::Error::Host::Event::errName);
    }

    return 0;
}


void send_esel(uint16_t recordid) {
	char *desc, *assoc;
	const char *sev;
	uint8_t *buffer = NULL;
	const char *path = "/tmp/esel";
	ssize_t sz;
	int r;

	sz = getfilestream(path, &buffer);
	if (sz == 0) {
		printf("Error file does not exist %d\n",__LINE__);
		return;
	}

	sev = create_esel_severity(buffer);
	create_esel_association(buffer, &assoc);
	create_esel_description(buffer, sev, &desc);

	r = send_esel_to_dbus(desc, sev, assoc, buffer, sz);
	if (r < 0) {
		fprintf(stderr, "Failed to send esel to dbus\n");
	}

	free(assoc);
	free(desc);
	delete[] buffer;

	return;
}
