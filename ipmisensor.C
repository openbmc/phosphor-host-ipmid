#include <stdio.h>
#include <string.h>
#include <stdint.h>


extern uint8_t find_sensor(uint8_t);
extern int set_sensor_dbus_state_v(uint8_t , const char *, char *);


struct sensorRES_t {
	uint8_t sensor_number;
	uint8_t operation;
	uint8_t sensor_reading;
	uint8_t assert_state7_0;
	uint8_t assert_state14_8;	
	uint8_t deassert_state7_0;
	uint8_t deassert_state14_8;	
	uint8_t event_data1;
	uint8_t event_data2;
	uint8_t event_data3;	
} __attribute__ ((packed));

#define ISBITSET(x,y) (((x)>>(y))&0x01)
#define ASSERTINDEX 0
#define DEASSERTINDEX 1

// Sensor Type,  Offset, function handler, Dbus Method, Assert value, Deassert value
struct lookup_t {
	uint8_t sensor_type;
	uint8_t offset;
	int (*func)(const sensorRES_t *, const lookup_t *, const char *);
	char    method[16];
	char    assertion[16];
	char    deassertion[16];
};


extern int updateDbusInterface(uint8_t , const char *, const char *) ;
extern int set_sensor_dbus_state(uint8_t ,const char *, const char *);


int set_sensor_dbus_state_simple(const sensorRES_t *pRec, const lookup_t *pTable, const char *value) {

	return set_sensor_dbus_state(pRec->sensor_number, pTable->method, value);
}

struct event_data_t {
	uint8_t data;
	char    text[32];
};

event_data_t g_fwprogress02h[] = {
	{0x00, "Unspecified"},
	{0x01, "Memory Init"},
	{0x02, "HD Init"},
	{0x03, "Secondary Proc Init"},
	{0x04, "User Authentication"},
	{0x05, "User init system setup"},
	{0x06, "USB configuration"},
	{0x07, "PCI configuration"},
	{0x08, "Option ROM Init"},
	{0x09, "Video Init"},
	{0x0A, "Cache Init"},
	{0x0B, "SM Bus init"},
	{0x0C, "Keyboard Init"},
	{0x0D, "Embedded ctrl init"},
	{0x0E, "Docking station attachment"},
	{0x0F, "Enable docking station"},
	{0x10, "Docking station ejection"},
	{0x11, "Disabling docking station"},
	{0x12, "Calling OS Wakeup"},
	{0x13, "Starting OS"},
	{0x14, "Baseboard Init"},
	{0x15, ""},
	{0x16, "Floppy Init"},
	{0x17, "Keyboard Test"},
	{0x18, "Pointing Device Test"},
	{0x19, "Primary Proc Init"},
	{0xFF, "Unknown"}
};


char *getfw02string(uint8_t b) {

	event_data_t *p = g_fwprogress02h;

	while(p->data != 0xFF) {
		if (p->data == b) {
			break;
		}
		p++;
	}

	return p->text;
}
//  The fw progress sensor contains some additional information that needs to be processed
//  prior to calling the dbus code.  
int set_sensor_dbus_state_fwprogress(const sensorRES_t *pRec, const lookup_t *pTable, const char *value) {

	char valuestring[64];
	char* p = valuestring;

	switch (pTable->offset) {

		case 0x00 : snprintf(p, sizeof(valuestring), "POST Error, 0x%02x", pRec->event_data2);
					break;
		case 0x01 : snprintf(p, sizeof(valuestring), "FW Hang, 0x%02x", pRec->event_data2);
					break;
		case 0x02 : snprintf(p, sizeof(valuestring), "FW Progress, %s", getfw02string(pRec->event_data2));
					break;
	}

	return set_sensor_dbus_state_v(pRec->sensor_number, pTable->method, p);
}

// Handling this special OEM sensor by coping what is in byte 4.  I also think that is odd
// considering byte 3 is for sensor reading.  This seems like a misuse of the IPMI spec
int set_sensor_dbus_state_osboot(const sensorRES_t *pRec, const lookup_t *pTable, const char *value) {
	char valuestring[32];
	char* pStr = valuestring;

	sprintf(valuestring, "%d", pRec->assert_state7_0);

	return set_sensor_dbus_state_v(pRec->sensor_number, pTable->method, pStr);
}


//  This table lists only senors we care about telling dbus about.
//  Offset definition cab be found in section 42.2 of the IPMI 2.0
//  spec.  Add more if/when there are more items of interest.
lookup_t g_ipmidbuslookup[] = {

	{0x07, 0x00, set_sensor_dbus_state_simple, "setPresent", "False", "False"}, // OCC Inactive 0
	{0x07, 0x01, set_sensor_dbus_state_simple, "setPresent", "True", "True"},   // OCC Active 1
	{0x07, 0x07, set_sensor_dbus_state_simple, "setPresent", "True", "False"},
	{0x07, 0x08, set_sensor_dbus_state_simple, "setFault",   "True", ""},
	{0x0C, 0x06, set_sensor_dbus_state_simple, "setPresent", "True", "False"},
	{0x0C, 0x04, set_sensor_dbus_state_simple, "setFault",   "True", ""},
	{0x0F, 0x02, set_sensor_dbus_state_fwprogress, "setValue", "True", "False"},
	{0x0F, 0x01, set_sensor_dbus_state_fwprogress, "setValue", "True", "False"},
	{0x0F, 0x00, set_sensor_dbus_state_fwprogress, "setValue", "True", "False"},
	{0xC7, 0x01, set_sensor_dbus_state_simple, "setFault", "True", ""},
	{0xc3, 0x00, set_sensor_dbus_state_osboot, "setValue", "" ,""},

	{0xFF, 0xFF, NULL, "", "", ""}
};



void reportSensorEventAssert(sensorRES_t *pRec, int index) {
	lookup_t *pTable = &g_ipmidbuslookup[index];
	(*pTable->func)(pRec, pTable, pTable->assertion);
}
void reportSensorEventDeassert(sensorRES_t *pRec, int index) {
	lookup_t *pTable = &g_ipmidbuslookup[index];
	(*pTable->func)(pRec, pTable, pTable->deassertion);
}


int findindex(const uint8_t sensor_type, int offset, int *index) {
	
	int i=0, rc=0;
	lookup_t *pTable = g_ipmidbuslookup;

	do {
		if ( ((pTable+i)->sensor_type == sensor_type) && 
			 ((pTable+i)->offset  == offset) ) {
			rc = 1;
			*index = i;
			break;
		}
		i++;
	} while ((pTable+i)->sensor_type  != 0xFF);

	return rc;
}

void debug_print_ok_to_dont_care(uint8_t stype, int offset)
{
	printf("LOOKATME: Sensor should not be reported:  Type 0x%02x, Offset 0x%02x\n",
		stype, offset);
}

bool shouldReport(uint8_t sensorType, int offset, int *index) {

	bool rc = false;

	if (findindex(sensorType, offset, index)) { rc = true;	}

	if (rc==false) { debug_print_ok_to_dont_care(sensorType, offset); }

	return rc;
}


int updateSensorRecordFromSSRAESC(const void *record) {

	sensorRES_t *pRec = (sensorRES_t *) record;
	uint8_t stype;
	int index, i=0;
	stype = find_sensor(pRec->sensor_number);


	// 0xC3 types use the assertion7_0 for the value to be set
	// so skip the reseach and call the correct event reporting
	// function
	if (stype == 0xC3) {

		shouldReport(stype, 0x00, &index);
		reportSensorEventAssert(pRec, index);

	} else {
		// Scroll through each bit position .  Determine
		// if any bit is either asserted or Deasserted.
		for(i=0;i<8;i++) {
			if ((ISBITSET(pRec->assert_state7_0,i))  &&
				(shouldReport(stype, i, &index)))
			{
				reportSensorEventAssert(pRec, index);
			}
			if ((ISBITSET(pRec->assert_state14_8,i))  &&
				(shouldReport(stype, i+8, &index)))
			{
				reportSensorEventAssert(pRec, index);
			}
			if ((ISBITSET(pRec->deassert_state7_0,i))  &&
				(shouldReport(stype, i, &index)))
			{
				reportSensorEventDeassert(pRec, index);
			}
			if ((ISBITSET(pRec->deassert_state14_8,i))  &&
				(shouldReport(stype, i+8, &index)))
			{
				reportSensorEventDeassert(pRec, index);
			}
		}

	}


	return 0;
}
