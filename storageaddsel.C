#include <stdint.h>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <vector>
#include <memory>
#include <systemd/sd-bus.h>

#include "ipmid.H"
#include "storagehandler.h"
#include "sensorhandler.h"

using namespace std;

extern int find_openbmc_path(const char *, const uint8_t , dbus_interface_t *);


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
	char r;

	r = find_openbmc_path("SENSOR", sensor_number, &a);

	if ((r < 0) || (a.bus[0] == 0)) {
		// Just make a generic message for errors that
		// occur on sensors that dont exist
		asprintf(s, "Unknown Sensor (0x%02x)", sensor_number);
	} else {

		if ((p = strrchr (a.path, '/')) == NULL) {
			p = "/Unknown Sensor";
		}

		asprintf(s, "%s", p+1);
	}

	return 0;
}


size_t getfilestream(const char *fn, uint8_t **buffer) {

	FILE *fp;
	size_t size = 0;

	if ((fp = fopen(fn, "rb")) != NULL) {

		fseek(fp, 0, SEEK_END);
		size = ftell(fp);
		fseek(fp, 0, SEEK_SET);

		*buffer = new uint8_t [size];

		fread(*buffer, 1, size, fp);
		fclose(fp);
	}

	return size;
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

	asprintf(m, "%s", dbusint.path);

	return 0;
}



int create_esel_description(const uint8_t *buffer, const char *sev, char **message) {


	ipmi_add_sel_request_t *p;
	char *m;

	p =  ( ipmi_add_sel_request_t *) buffer;

	find_sensor_type_string(p->sensornumber,&m);

	asprintf(message, "A %s has experienced a %s", m, sev );

	free(m);

	return 0;
}


int send_esel_to_dbus(const char *desc, const char *sev, const char *details, uint8_t *debug, size_t debuglen) {

	sd_bus *mbus = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = NULL, *m=NULL;
    uint16_t x;
    int r;

    mbus = ipmid_get_sd_bus_connection();

    r = sd_bus_message_new_method_call(mbus,&m,
    									"org.openbmc.records.events",
    									"/org/openbmc/records/events",
    									"org.openbmc.recordlog",
    									"acceptHostMessage");
    if (r < 0) {
        fprintf(stderr, "Failed to add the method object: %s\n", strerror(-r));
        goto finish;
    }

    r = sd_bus_message_append(m, "sss", desc, sev, details);
    if (r < 0) {
        fprintf(stderr, "Failed add the message strings : %s\n", strerror(-r));
        goto finish;
    }

    r = sd_bus_message_append_array(m, 'y', debug, debuglen);
    if (r < 0) {
        fprintf(stderr, "Failed to add the raw array of bytes: %s\n", strerror(-r));
        goto finish;
    }
    // Call the IPMI responder on the bus so the message can be sent to the CEC
    r = sd_bus_call(mbus, m, 0, &error, &reply);
    if (r < 0) {
        fprintf(stderr, "Failed to call the method: %s %s\n", __FUNCTION__, strerror(-r));
        goto finish;
    }
    r = sd_bus_message_read(reply, "q", &x);
    if (r < 0) {
        fprintf(stderr, "Failed to get a rc from the method: %s\n", strerror(-r));
    }

finish:
    sd_bus_error_free(&error);
    m = sd_bus_message_unref(m);
    reply = sd_bus_message_unref(reply);
    return r;
}


void send_esel(uint16_t recordid) {
	char *desc, *assoc;
	const char *sev;
	uint8_t *buffer = NULL;
	const char *path = "/tmp/esel";
	size_t sz;

	sz = getfilestream(path, &buffer);
	if (sz == 0) {
		printf("Error file does not exist %d\n",__LINE__);
		return;
	}

	sev = create_esel_severity(buffer);
	create_esel_association(buffer, &assoc);
	create_esel_description(buffer, sev, &desc);

	send_esel_to_dbus(desc, sev, assoc, buffer, sz);

	free(assoc);
	free(desc);
	delete[] buffer;

	return;
}
