COMMON_CXX = \
	-flto \
	-Wno-psabi \
	$(SDBUSPLUS_CFLAGS) \
	$(SYSTEMD_CFLAGS) \
	$(libmapper_CFLAGS) \
	$(SDBUSPLUS_CFLAGS) \
	$(PHOSPHOR_LOGGING_CFLAGS) \
	$(PHOSPHOR_DBUS_INTERFACES_CFLAGS) \
	-DBOOST_ERROR_CODE_HEADER_ONLY \
	-DBOOST_SYSTEM_NO_DEPRECATED \
	-DBOOST_COROUTINES_NO_DEPRECATION_WARNING \
	-DBOOST_ASIO_DISABLE_THREADS \
	-DBOOST_ALL_NO_LIB

lib_LTLIBRARIES = libuserlayer.la libchannellayer.la
libuserlayer_la_SOURCES = \
	user_layer.cpp \
	user_mgmt.cpp \
	passwd_mgr.cpp \
	channel_mgmt.cpp \
	channel_layer.cpp
libuserlayer_la_LDFLAGS = \
	$(SYSTEMD_LIBS) \
	$(libmapper_LIBS) \
	$(PHOSPHOR_LOGGING_LIBS) \
	$(PHOSPHOR_DBUS_INTERFACES_LIBS) \
	-lstdc++fs \
	$(CRYPTO_LIBS) \
	-version-info 0:0:0 -shared
libuserlayer_la_CXXFLAGS = \
	-I$(top_srcdir) \
	$(COMMON_CXX)

libchannellayer_la_SOURCES =
libchannellayer_la_LDFLAGS = \
	$(SYSTEMD_LIBS) \
	$(libmapper_LIBS) \
	$(PHOSPHOR_LOGGING_LIBS) \
	$(PHOSPHOR_DBUS_INTERFACES_LIBS) \
	-lstdc++fs \
	-version-info 0:0:0 -shared
libchannellayer_la_CXXFLAGS = \
	$(SYSTEMD_CFLAGS) \
	$(libmapper_CFLAGS) \
	$(PHOSPHOR_LOGGING_CFLAGS) \
	$(PHOSPHOR_DBUS_INTERFACES_CFLAGS)
