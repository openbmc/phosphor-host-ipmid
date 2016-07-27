# Check only what's absolutely necessary for building, i.e) ignore existence of 'NEWS' file
AUTOMAKE_OPTIONS = foreign

AM_DEFAULT_SOURCE_EXT = .cpp

AM_CPPFLAGS = -DHOST_IPMI_LIB_PATH=\"/usr/lib/host-ipmid/\"
AM_CXXFLAGS = -std=c++14 -fpic -Wall -Wno-unused-result $(SYSTEMD_CFLAGS) $(SYSTEMD_LIBS)

testit_SOURCES = \
	ipmisensor.cpp \
	testit.cpp
testit_CXXFLAGS = $(AM_CXXFLAGS) -rdynamic -ldl

#testaddsel_SOURCES = \
#	testaddsel.cpp \
#	storageaddsel.cpp
#testaddsel_CXXFLAGS = $(AM_CXXFLAGS) -rdynamic -ldl

ipmid_SOURCES = \
	ipmid.cpp
	ipmiwhitelist.cpp
nodist_ipmid_SOURCES = ipmiwhitelist.cpp
#BUILT_SOURCES = ipmiwhitelist.cpp
CLEANFILES = ipmiwhitelist.cpp
ipmiwhitelist.cpp: Makefile
	./generate_whitelist.sh host-ipmid-whitelist.conf > $@
ipmid_CXXFLAGS = $(AM_CXXFLAGS) -rdynamic -lmapper -ldl

libapphandlerdir = /usr/lib/host-ipmid
libapphandler_LTLIBRARIES = libapphandler.la
libapphandler_la_SOURCES = \
	apphandler.cpp \
	sensorhandler.cpp \
	storagehandler.cpp \
	chassishandler.cpp \
	dcmihandler.cpp \
	ipmisensor.cpp \
	storageaddsel.cpp \
	transporthandler.cpp \
	globalhandler.cpp \
	groupext.cpp
libapphandler_la_LDFLAGS = $(LDFLAGS) -shared
libapphandler_la_CXXFLAGS = $(AM_CXXFLAGS) -lmapper

libhostservicedir = /usr/lib/host-ipmid
libhostservice_LTLIBRARIES = libhostservice.la
libhostservice_la_SOURCES = \
	host-services.c
libhostservice_la_LDFLAGS = $(LDFLAGS) -shared

libdir = /usr/lib/host-ipmid
includedir = /usr/include/host-ipmid

include_HEADERS = \
	ipmid-api.h

#default sbin dir
sbin_PROGRAMS = \
	ipmid

check_PROGRAMS = \
	testit
#	testaddsel
