CXX ?= $(CROSS_COMPILE)g++

TESTER = testit

TESTADDSEL = testaddsel

DAEMON = ipmid
DAEMON_OBJ  =  ipmid.o \
               ipmiwhitelist.o

LIB_APP_OBJ = apphandler.o     \
              sensorhandler.o  \
              storagehandler.o \
              chassishandler.o \
              dcmihandler.o    \
              ipmisensor.o     \
              storageaddsel.o  \
              transporthandler.o  \
              globalhandler.o  \
              groupext.o

LIB_HOST_SRV_OBJ = host-services.o

TESTADDSEL_OBJ = $(TESTADDSEL).o \
                 storageaddsel.o

TESTER_OBJ = ipmisensor.o 	   \
	     testit.o

LIB_APP     = libapphandler.so
LIB_HOST_SRV = libhostservice.so

INSTALLED_LIBS += $(LIB_APP) $(LIB_HOST_SRV)
INSTALLED_HEADERS = ipmid-api.h

CXXFLAGS += -Wall -Wno-unused-result
CFLAGS += -Wall -Wno-unused-result

INC_FLAG += $(shell pkg-config --cflags --libs libsystemd) -I. -O2
LIB_FLAG += $(shell pkg-config  --libs libsystemd) -rdynamic
IPMID_PATH ?= -DHOST_IPMI_LIB_PATH=\"/usr/lib/host-ipmid/\"

DESTDIR ?= /
SBINDIR ?= /usr/sbin
INCLUDEDIR ?= /usr/include
LIBDIR ?= /usr/lib

WHITELIST_SRC = ipmiwhitelist.C
WHITELIST_CONF ?= host-ipmid-whitelist.conf

all: $(DAEMON) $(LIB_APP) $(LIB_HOST_SRV) $(TESTER)

$(WHITELIST_SRC) : generate_whitelist.sh $(WHITELIST_CONF)
	./$^ > $@

%.o: %.cpp
	$(CXX) -std=c++14 -fpic -c $< $(CXXFLAGS) $(INC_FLAG) $(IPMID_PATH) -o $@

$(LIB_APP): $(LIB_APP_OBJ)
	$(CXX) $^ -shared $(LDFLAGS) $(LIB_FLAG) -o $@ -lmapper

$(LIB_HOST_SRV): $(LIB_HOST_SRV_OBJ)
	$(CXX) $^ -shared $(LDFLAGS) $(LIB_FLAG) -o $@

$(DAEMON): $(DAEMON_OBJ)
	$(CXX) $^ $(LDFLAGS) $(LIB_FLAG) -o $@ -lmapper -ldl

$(TESTER): $(TESTER_OBJ)
	$(CXX) $^ $(LDFLAGS) $(LIB_FLAG) -o $@ -ldl

clean:
	rm -f $(DAEMON) $(TESTER) *.o *.so $(WHITELIST_SRC)

$(TESTADDSEL): $(TESTADDSEL_OBJ)
	$(CXX) $^ $(LDFLAGS) $(LIB_FLAG) -o $@ -ldl

install:
		install -m 0755 -d $(DESTDIR)$(SBINDIR)
		install -m 0755 ipmid $(DESTDIR)$(SBINDIR)
		install -m 0755 -d $(DESTDIR)$(LIBDIR)/host-ipmid
		install -m 0755 $(INSTALLED_LIBS) $(DESTDIR)$(LIBDIR)/host-ipmid
		install -m 0755 -d $(DESTDIR)$(INCLUDEDIR)/host-ipmid
		install -m 0644 $(INSTALLED_HEADERS) $(DESTDIR)$(INCLUDEDIR)/host-ipmid


