AM_DEFAULT_SOURCE_EXT = .cpp
AM_CPPFLAGS = -I$(top_srcdir)
sbin_PROGRAMS = phosphor-softpoweroff

phosphor_softpoweroff_SOURCES = \
                    softoff.cpp \
                    timer.cpp   \
                    mainapp.cpp \
                    xyz/openbmc_project/Ipmi/Internal/server.cpp

BUILT_SOURCES = server_dbus.cpp
nodist_include_HEADERS = server_dbus.hpp
nodist_SOURCE = server_dbus.cpp
CLEANFILES = server_dbus.cpp server_dbus.hpp

phosphor_softpoweroff_LDFLAGS = $(SYSTEMD_LIBS) $(SDBUSPLUS_LIBS)
phosphor_softpoweroff_CXXFLAGS = $(SYSTEMD_CFLAGS) $(SDBUSPLUS_CFLAGS)

-include Makefile.interfaces
