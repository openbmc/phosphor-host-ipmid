#include <stdio.h>
#include <string.h>
#include <stdint.h>


extern unsigned char findSensor(char);

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

#define ISBITSET(x,y) ((x>>y)&0x01)
#define ASSERTINDEX 0
#define DEASSERTINDEX 1


extern int updateDbusInterface(uint8_t , const char *, const char *) ;
extern int set_sensor_dbus_state(uint8_t ,const char *, const char *);



// Sensor Type,  Offset, function handler, Dbus Method, Assert value, Deassert value
struct lookup_t {
	uint8_t sensor_type;
	uint8_t offset;
	int (*func)(uint8_t, const char *, const char *);
	char    method[16];
	char    assertion[16];
	char    deassertion[16];
};


//  This table lists only senors we care about telling dbus about.
//  Offset definition cab be found in section 42.2 of the IPMI 2.0 
//  spec.  Add more if/when there are more items of interest.
lookup_t ipmidbuslookup[] = {

	{0x07, 0x07, set_sensor_dbus_state, "setPresent", "True", "False"},
	{0x07, 0x08, set_sensor_dbus_state, "setFault",   "True", "False"},
	{0x0C, 0x06, set_sensor_dbus_state, "setPresent", "True", "False"},
	{0x0C, 0x04, set_sensor_dbus_state, "setFault",   "True", "False"},
	{0xFF, 0xFF, NULL,                  "",            "" ,    ""}
};

int findindex(const uint8_t sensor_type, int offset, int *index) {
	
	int i=0, rc=0;
	lookup_t *pTable = ipmidbuslookup;

	do {

		if ( ((pTable+i)->sensor_type == sensor_type) && 
			 ((pTable+i)->offset  == offset)  ) {
			rc = 1;
			*index = i;
			break;
		}
		i++;
	} while ((pTable+i)->sensor_type  != 0xFF);

	return rc;
}

int shouldReport(sensorRES_t *pRec, uint8_t sensorType, int offset, int assertState) {

	int index;
	char *pState;
	lookup_t *pTable = ipmidbuslookup;

	if (findindex(sensorType, offset, &index)) {

		if (assertState == ASSERTINDEX) {
			pState = (pTable+index)->assertion;
		} else {
			pState = (pTable+index)->deassertion;
		}
		(*((pTable+index)->func))(pRec->sensor_number, (pTable+index)->method, pState);
	}

	return 0;
}


int updateSensorRecordFromSSRAESC(const void *record) {

	sensorRES_t *pRec = (sensorRES_t *) record;
	unsigned char stype;
	int index, i=0;

	stype = findSensor(pRec->sensor_number);

	// Scroll through each bit position .  Determine 
	// if any bit is either asserted or Deasserted.
	for(i=0;i<8;i++) {
		if (ISBITSET(pRec->assert_state7_0,i)) { 
			shouldReport(pRec, stype, i, ASSERTINDEX);
		}
		if (ISBITSET(pRec->assert_state14_8,i)) { 
			shouldReport(pRec, stype, i+8, ASSERTINDEX);
		}
		if (ISBITSET(pRec->deassert_state7_0,i)) { 
			shouldReport(pRec, stype, i, DEASSERTINDEX);
		}
		if (ISBITSET(pRec->deassert_state14_8,i)) { 
			shouldReport(pRec, stype, i+8, DEASSERTINDEX);
		}
	}

	return 0;
}
