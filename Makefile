CXX ?= $(CROSS_COMPILE)g++

TESTER = testit

TESTADDSEL = testaddsel

DAEMON = ipmid
DAEMON_OBJ  = $(DAEMON).o

LIB_APP_OBJ = apphandler.o     \
              sensorhandler.o  \
              dcmihandler.o    \
              ipmisensor.o     \
              storageaddsel.o  

TESTADDSEL_OBJ = $(TESTADDSEL).o \
                 storageaddsel.o

TESTER_OBJ = ipmisensor.o 	   \
	     testit.o

LIB_STRG_OBJ = storagehandler.o \
               storageaddsel.o

TESTER_OBJ = ipmisensor.o  \
			 testit.o

LIB_APP    = libapphandler.so
LIB_STRG   = libstoragehandler.so
 
INSTALLED_LIBS += $(LIB_APP) $(LIB_STRG)
INSTALLED_HEADERS = ipmid-api.h

INC_FLAG += $(shell pkg-config --cflags --libs libsystemd) -I. -O2
LIB_FLAG += $(shell pkg-config  --libs libsystemd) -rdynamic
IPMID_PATH ?= -DHOST_IPMI_LIB_PATH=\"/usr/lib/host-ipmid/\"

DESTDIR ?= /
SBINDIR ?= /usr/sbin
INCLUDEDIR ?= /usr/include
LIBDIR ?= /usr/lib

all: $(DAEMON) $(LIB_APP) $(LIB_STRG) $(TESTER)

%.o: %.C
	$(CXX) --std=gnu++14 -fpic -c $< $(CXXFLAGS) $(INC_FLAG) $(IPMID_PATH) -o $@

$(LIB_APP): $(LIB_APP_OBJ)
	$(CXX) $^ -shared $(LDFLAGS) $(LIB_FLAG) -o $@ -ldl

$(LIB_STRG): $(LIB_STRG_OBJ)
	$(CXX) $^ -shared $(LDFLAGS) $(LIB_FLAG) -o $@ -ldl -lifp

$(DAEMON): $(DAEMON_OBJ)
	$(CXX) $^ $(LDFLAGS) $(LIB_FLAG) -o $@ -ldl

$(TESTER): $(TESTER_OBJ)
	$(CXX) $^ $(LDFLAGS) $(LIB_FLAG) -o $@ -ldl

clean:
	rm -f $(DAEMON) $(TESTER) *.o *.so

$(TESTADDSEL): $(TESTADDSEL_OBJ)
	$(CXX) $^ $(LDFLAGS) $(LIB_FLAG) -o $@ -ldl
		
install:
		install -m 0755 -d $(DESTDIR)$(SBINDIR)
		install -m 0755 ipmid $(DESTDIR)$(SBINDIR)
		install -m 0755 -d $(DESTDIR)$(LIBDIR)/host-ipmid
		install -m 0755 $(INSTALLED_LIBS) $(DESTDIR)$(LIBDIR)/host-ipmid
		install -m 0755 -d $(DESTDIR)$(INCLUDEDIR)/host-ipmid
		install -m 0644 $(INSTALLED_HEADERS) $(DESTDIR)$(INCLUDEDIR)/host-ipmid
