CXX ?= $(CROSS_COMPILE)g++

DAEMON = ipmid
DAEMON_OBJ  = $(DAEMON).o
LIB_APP_OBJ = apphandler.o     \
              sensorhandler.o  \
              storagehandler.o \
              dcmihandler.o    \
              ipmisensor.o

LIB_APP     = libapphandler.so

INC_FLAG += $(shell pkg-config --cflags --libs libsystemd) -I. -O2 --std=gnu++11
LIB_FLAG += $(shell pkg-config  --libs libsystemd) -rdynamic
IPMID_PATH ?= -DHOST_IPMI_LIB_PATH=\"/usr/lib/host-ipmid/\" 

all: $(DAEMON) $(LIB_APP) 

%.o: %.C
	$(CXX) -fpic -c $< $(CXXFLAGS) $(INC_FLAG) $(IPMID_PATH) -o $@

$(LIB_APP): $(LIB_APP_OBJ)
	$(CXX) $^ -shared $(LDFLAGS) $(LIB_FLAG) -o $@

$(DAEMON): $(DAEMON_OBJ)
	$(CXX) $^ $(LDFLAGS) $(LIB_FLAG) -o $@ -ldl

clean:
	rm -f $(DAEMON) *.o *.so