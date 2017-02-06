AM_DEFAULT_SOURCE_EXT = .cpp
sbin_PROGRAMS = phosphor-softpoweroff

phosphor_softpoweroff_SOURCES = \
                    softoff.cpp \
                    timer.cpp   \
                    mainapp.cpp \
                    xyz/openbmc_project/Ipmi/Internal/server.cpp

BUILT_SOURCES = server_dbus.cpp
nodist_include_HEADERS = server_dbus.hpp
CLEANFILES = server_dbus.cpp server_dbus.hpp

phosphor_softpoweroff_LDFLAGS = $(SYSTEMD_LIBS)

-include Makefile.interfaces

SUBDIRS = test
