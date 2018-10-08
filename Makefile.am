AM_DEFAULT_SOURCE_EXT = .cpp

sbin_PROGRAMS = \
	ipmid

ipmid_SOURCES = \
	ipmid-new.cpp \
	settings.cpp \
	host-cmd-manager.cpp \
	utils.cpp

nodist_ipmid_SOURCES = ipmiwhitelist.cpp

libipmi20_BUILT_LIST = \
	sensor-gen.cpp \
	inventory-sensor-gen.cpp \
	fru-read-gen.cpp \
	channel-gen.cpp

BUILT_SOURCES = \
	ipmiwhitelist.cpp \
	$(libipmi20_BUILT_LIST)

CLEANFILES = $(BUILT_SOURCES)

BOOST_CXX = \
	-DBOOST_ERROR_CODE_HEADER_ONLY \
	-DBOOST_SYSTEM_NO_DEPRECATED \
	-DBOOST_COROUTINES_NO_DEPRECATION_WARNING \
	-DBOOST_ALL_NO_LIB

ipmid_CXXFLAGS = \
	$(BOOST_CXX) \
	$(PHOSPHOR_LOGGING_CFLAGS) \
	$(PHOSPHOR_DBUS_INTERFACES_CFLAGS) \
	-flto
ipmid_LDFLAGS = \
	$(SYSTEMD_LIBS) \
	$(libmapper_LIBS) \
	$(LIBADD_DLOPEN) \
	$(PHOSPHOR_LOGGING_LIBS) \
	$(PHOSPHOR_DBUS_INTERFACES_LIBS) \
	$(CRYPTO_LIBS) \
	-lboost_coroutine \
	-lstdc++fs \
	-pthread \
	-export-dynamic

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

channel-gen.cpp:
	$(AM_V_GEN)@CHANNELGEN@ -o $(top_builddir) generate-cpp

libuserlayerdir = ${libdir}
libuserlayer_LTLIBRARIES = libuserlayer.la
libuserlayer_la_SOURCES = \
        user_channel/user_layer.cpp \
        user_channel/user_mgmt.cpp \
        user_channel/passwd_mgr.cpp \
        user_channel/channel_mgmt.cpp \
        user_channel/channel_layer.cpp

libuserlayer_la_LDFLAGS = \
	$(SYSTEMD_LIBS) \
	$(libmapper_LIBS) \
	$(PHOSPHOR_LOGGING_LIBS) \
	$(PHOSPHOR_DBUS_INTERFACES_LIBS) \
	-lstdc++fs \
	$(LIBPAM) $(LIBCRYPT) -lpam_misc -lssl \
	-version-info 0:0:0 -shared
libuserlayer_la_CXXFLAGS = \
	$(SYSTEMD_CFLAGS) \
	$(libmapper_CFLAGS) \
	$(PHOSPHOR_LOGGING_CFLAGS) \
	$(PHOSPHOR_DBUS_INTERFACES_CFLAGS)

libipmi20dir = ${libdir}/ipmid-providers
libipmi20_LTLIBRARIES = libipmi20.la
libipmi20_la_DEPENDENCIES = libuserlayer.la
libipmi20_la_SOURCES = \
	net.cpp \
	app/channel.cpp \
	app/watchdog.cpp \
	app/watchdog_service.cpp \
	apphandler.cpp \
	sys_info_param.cpp \
	sensorhandler.cpp \
	storagehandler.cpp \
	chassishandler.cpp \
	dcmihandler.cpp \
	ipmisensor.cpp \
	storageaddsel.cpp \
	transporthandler.cpp \
	globalhandler.cpp \
	groupext.cpp \
	utils.cpp \
	selutility.cpp \
	ipmi_fru_info_area.cpp \
	read_fru_data.cpp \
	sensordatahandler.cpp \
	user_channel/usercommands.cpp \
	user_channel/channelcommands.cpp \
	$(libipmi20_BUILT_LIST)

@CODE_COVERAGE_RULES@

check_PROGRAMS =
XFAIL_TESTS =

TESTS = $(check_PROGRAMS)

libipmi20_la_LDFLAGS = \
	$(SYSTEMD_LIBS) \
	$(libmapper_LIBS) \
	$(PHOSPHOR_LOGGING_LIBS) \
	$(PHOSPHOR_DBUS_INTERFACES_LIBS) \
	-lstdc++fs \
	-luserlayer \
	-lboost_coroutine \
	-version-info 0:0:0 -shared
libipmi20_la_CXXFLAGS = \
	$(SYSTEMD_CFLAGS) \
	$(libmapper_CFLAGS) \
	$(BOOST_CXX) \
	$(PHOSPHOR_LOGGING_CFLAGS) \
	$(PHOSPHOR_DBUS_INTERFACES_CFLAGS) \
	-flto

libsysintfcmdsdir = ${libdir}/ipmid-providers
libsysintfcmds_LTLIBRARIES = libsysintfcmds.la
libsysintfcmds_la_SOURCES = \
	systemintfcmds.cpp \
	host-interface.cpp
libsysintfcmds_la_LDFLAGS = \
	$(SYSTEMD_LIBS) \
	$(libmapper_LIBS) \
	$(PHOSPHOR_DBUS_INTERFACES_LIBS) \
	$(PHOSPHOR_LOGGING_LIBS) \
	$(SDBUSPLUS_LIBS) \
	-version-info 0:0:0 -shared
libsysintfcmds_la_CXXFLAGS = \
	$(SYSTEMD_CFLAGS) \
	$(BOOST_CXX) \
	$(libmapper_CFLAGS) \
	$(PHOSPHOR_DBUS_INTERFACES_CFLAGS) \
	$(PHOSPHOR_LOGGING_CFLAGS) \
	$(SDBUSPLUS_CFLAGS) \
	-flto

nobase_include_HEADERS = \
	ipmi/ipmi-api.hpp \
	ipmi/handler.hpp \
	ipmi/message.hpp \
	ipmi/message/pack.hpp \
	ipmi/message/types.hpp \
	ipmi/message/unpack.hpp \
	ipmi/registration.hpp \
	host-ipmid/iana.hpp \
	user_channel/user_layer.hpp \
	user_channel/channel_layer.hpp \
	host-ipmid/ipmid-api.h \
	host-ipmid/ipmid-host-cmd.hpp \
	host-ipmid/ipmid-host-cmd-utils.hpp \
	host-ipmid/oemopenbmc.hpp \
	host-ipmid/oemrouter.hpp

# Forcing the build of self and then subdir
SUBDIRS = . test softoff
