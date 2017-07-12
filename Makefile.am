AM_DEFAULT_SOURCE_EXT = .cpp

sbin_PROGRAMS = \
	ipmid

ipmid_SOURCES = \
	ipmid.cpp \
	host-cmd-manager.cpp \
	timer.cpp \
	utils.cpp
nodist_ipmid_SOURCES = ipmiwhitelist.cpp
BUILT_SOURCES = \
               ipmiwhitelist.cpp \
               sensor-gen.cpp \
               inventory-sensor-gen.cpp \
               fru-read-gen.cpp

CLEANFILES = $(BUILT_SOURCES)

#TODO - Make this path a configure option (bitbake parameter)
ipmid_CPPFLAGS = -DHOST_IPMI_LIB_PATH=\"/usr/lib/host-ipmid/\" \
                 $(PHOSPHOR_LOGGING_CFLAGS) \
                 $(PHOSPHOR_DBUS_INTERFACES_CFLAGS)
ipmid_LDFLAGS = $(SYSTEMD_LIBS) \
                $(libmapper_LIBS) \
                $(LIBADD_DLOPEN) \
                $(PHOSPHOR_LOGGING_LIBS) \
                $(PHOSPHOR_DBUS_INTERFACES_LIBS) -export-dynamic
# TODO: Rather than use -export-dynamic, we should use -export-symbol to have a
#       selective list of symbols.

ipmiwhitelist.cpp: ${srcdir}/generate_whitelist.sh $(WHITELIST_CONF)
	$(SHELL) $^ > $@

sensor-gen.cpp:
	$(AM_V_GEN)@SENSORGEN@ -o $(top_builddir) generate-cpp

inventory-sensor-gen.cpp:
	$(AM_V_GEN)@INVSENSORGEN@ -o $(top_builddir) generate-cpp

fru-read-gen.cpp:
	$(AM_V_GEN)@FRUGEN@ -o $(top_builddir) generate-cpp

libapphandlerdir = ${libdir}/ipmid-providers
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
	groupext.cpp \
	sensor-gen.cpp \
	utils.cpp \
	inventory-sensor-gen.cpp \
	fru-read-gen.cpp \
	selutility.cpp \
	ipmi_fru_info_area.cpp \
	read_fru_data.cpp

libapphandler_la_LDFLAGS = $(SYSTEMD_LIBS) $(libmapper_LIBS) $(PHOSPHOR_LOGGING_LIBS) $(PHOSPHOR_DBUS_INTERFACES_LIBS) -lstdc++fs -version-info 0:0:0 -shared
libapphandler_la_CXXFLAGS = $(SYSTEMD_CFLAGS) $(libmapper_CFLAGS) $(PHOSPHOR_LOGGING_CFLAGS) $(PHOSPHOR_DBUS_INTERFACES_CFLAGS)

libsysintfcmdsdir = ${libdir}/ipmid-providers
libsysintfcmds_LTLIBRARIES = libsysintfcmds.la
libsysintfcmds_la_SOURCES = \
	systemintfcmds.cpp \
	host-interface.cpp \
	utils.cpp \
	timer.cpp
libsysintfcmds_la_LDFLAGS = $(SYSTEMD_LIBS) \
                            $(libmapper_LIBS) \
                            $(PHOSPHOR_DBUS_INTERFACES_LIBS) \
                            $(PHOSPHOR_LOGGING_LIBS) \
                            $(SDBUSPLUS_LIBS) \
                            -version-info 0:0:0 -shared
libsysintfcmds_la_CXXFLAGS = $(SYSTEMD_CFLAGS) \
                             $(libmapper_CFLAGS) \
                             $(PHOSPHOR_DBUS_INTERFACES_CFLAGS) \
                             $(PHOSPHOR_LOGGING_CFLAGS) \
                             $(SDBUSPLUS_CFLAGS)

nobase_include_HEADERS = \
	host-ipmid/ipmid-api.h

# Forcing the build of self and then subdir
SUBDIRS = . test softoff
