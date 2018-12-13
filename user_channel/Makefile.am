lib_LTLIBRARIES = libuserlayer.la
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
	$(SYSTEMD_CFLAGS) \
	$(libmapper_CFLAGS) \
	$(PHOSPHOR_LOGGING_CFLAGS) \
	$(PHOSPHOR_DBUS_INTERFACES_CFLAGS)
