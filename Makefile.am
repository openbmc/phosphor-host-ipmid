sbin_PROGRAMS = \
	netipmid

netipmid_SOURCES = \
	endian.hpp \
	socket_channel.hpp \
	socket_channel.cpp \
	message.hpp \
	auth_algo.hpp \
	auth_algo.cpp \
	session.hpp \
	session.cpp \
	sessions_manager.hpp \
	sessions_manager.cpp \
	message_parsers.hpp \
	message_parsers.cpp \
	message_handler.hpp \
	message_handler.cpp \
	command_table.hpp \
	command_table.cpp \
	command/channel_auth.hpp \
	command/channel_auth.cpp \
	command/guid.hpp \
	command/guid.cpp \
	command/open_session.hpp \
	command/open_session.cpp \
	command/rakp12.hpp \
	command/rakp12.cpp \
	command/rakp34.hpp \
	command/rakp34.cpp \
	command/session_cmds.hpp \
	command/session_cmds.cpp \
	comm_module.hpp \
	comm_module.cpp \
	main.hpp \
	main.cpp \
	integrity_algo.hpp \
	integrity_algo.cpp \
	provider_registration.hpp \
	provider_registration.cpp \
	crypt_algo.hpp \
	crypt_algo.cpp \
	sol/console_buffer.hpp \
	sd_event_loop.hpp \
	sol/sol_context.hpp \
	sol/sol_manager.hpp \
	sd_event_loop.cpp \
	sol/sol_manager.cpp \
	sol/sol_context.cpp \
	command/sol_cmds.hpp \
	command/sol_cmds.cpp \
	command/payload_cmds.hpp \
	command/payload_cmds.cpp \
	sol_module.hpp \
	sol_module.cpp \
	settings.hpp \
	settings.cpp

netipmid_CPPFLAGS = -DNET_IPMID_LIB_PATH=\"/usr/lib/net-ipmid/\"


netipmid_LDFLAGS = \
	$(SYSTEMD_LIBS) \
	$(CRYPTO_LIBS) \
	$(libmapper_LIBS) \
	$(PHOSPHOR_LOGGING_LIBS) \
	$(PHOSPHOR_DBUS_INTERFACES_LIBS) \
	$(LIBADD_DLOPEN) \
	-export-dynamic

netipmid_CXXFLAGS = \
	-flto \
	$(SYSTEMD_CFLAGS) \
	$(libmapper_CFLAGS) \
	$(PHOSPHOR_LOGGING_CFLAGS) \
	$(PHOSPHOR_DBUS_INTERFACES_CFLAGS)

SUBDIRS = test

