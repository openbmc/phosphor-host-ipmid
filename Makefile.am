# Copyright © 2016 IBM Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

CC ?= $(CROSS_COMPILE)gcc
CXX ?= $(CROSS_COMPILE)g++

TESTER = testit

TESTADDSEL = testaddsel

DAEMON = ipmid
DAEMON_OBJ  = ipmid.o

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

INSTALLED_LIBS = $(LIB_APP) $(LIB_HOST_SRV)
include_HEADERS = ipmid-api.h

CXXFLAGS += -Wall -Wno-unused-result
CFLAGS += -Wall -Wno-unused-result

INC_FLAG = $(shell pkg-config --cflags --libs libsystemd) -I. -O2
LIB_FLAG = $(shell pkg-config  --libs libsystemd) -rdynamic
IPMID_PATH ?= -DHOST_IPMI_LIB_PATH=\"/usr/lib/host-ipmid/\"

DESTDIR ?= /
SBINDIR ?= /usr/sbin
INCLUDEDIR ?= /usr/include
LIBDIR ?= /usr/lib

all: $(DAEMON) $(LIB_APP) $(LIB_HOST_SRV) $(TESTER)

%.o: %.c
	$(CC) -c $< $(CFLAGS) $(INC_FLAG) $(IPMID_PATH) -o $@
%.o: %.cpp
	$(CXX) -std=c++14 -fpic -c $< $(CXXFLAGS) $(INC_FLAG) $(IPMID_PATH) -o $@

$(LIB_APP): $(LIB_APP_OBJ)
	$(CXX) $^ -shared $(LDFLAGS) $(LIB_FLAG) -o $@

$(LIB_HOST_SRV): $(LIB_HOST_SRV_OBJ)
	$(CXX) $^ -shared $(LDFLAGS) $(LIB_FLAG) -o $@

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
		install -m 0644 $(include_HEADERS) $(DESTDIR)$(INCLUDEDIR)/host-ipmid

