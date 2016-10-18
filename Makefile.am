AM_DEFAULT_SOURCE_EXT = .cpp

sbin_PROGRAMS = \
	ipmid

ipmid_SOURCES = \
	ipmid-router.cpp \
	dbus.cpp \
	ipmid.cpp
	ipmiwhitelist.cpp
nodist_ipmid_SOURCES = ipmiwhitelist.cpp
BUILT_SOURCES = ipmiwhitelist.cpp
CLEANFILES = ipmiwhitelist.cpp

#TODO - Make this path a configure option (bitbake parameter)
ipmid_CPPFLAGS = -DHOST_IPMI_LIB_PATH=\"/usr/lib/host-ipmid/\"
ipmid_LDFLAGS = $(SYSTEMD_LIBS) $(libmapper_LIBS) $(LIBADD_DLOPEN) -export-dynamic -lglog
# TODO: Rather than use -export-dynamic, we should use -export-symbol to have a
#       selective list of symbols.

WHITELIST_CONF ?= ${srcdir}/host-ipmid-whitelist.conf
ipmiwhitelist.cpp: ${srcdir}/generate_whitelist.sh $(WHITELIST_CONF)
	$(SHELL) $^ > $@


libapphandlerdir = ${libdir}/host-ipmid
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
libapphandler_la_LDFLAGS = $(SYSTEMD_LIBS) $(libmapper_LIBS) -version-info 0:0:0 -shared
libapphandler_la_CXXFLAGS = $(SYSTEMD_CFLAGS) $(libmapper_CFLAGS)

libhostservicedir = ${libdir}/host-ipmid
libhostservice_LTLIBRARIES = libhostservice.la
libhostservice_la_SOURCES = \
	host-services.c
libhostservice_la_LDFLAGS = $(SYSTEMD_LIBS) $(libmapper_LIBS) -version-info 0:0:0 -shared
libhostservice_la_CXXFLAGS = $(SYSTEMD_CFLAGS) $(libmapper_CFLAGS)

nobase_include_HEADERS = \
	host-ipmid/ipmid-api.h

SUBDIRS = test
