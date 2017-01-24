AM_DEFAULT_SOURCE_EXT = .cpp
sbin_PROGRAMS = phosphor-softpoweroff

phosphor_softpoweroff_SOURCES = \
                    softoff.cpp \
                    mainapp.cpp \
                    xyz.openbmc_project.Ipmi.Internal.SoftPowerOff.cpp

phosphor_softpoweroff_LDFLAGS = $(SYSTEMD_LIBS)
phosphor_sofpowertoff_CFLAGS = $(SYSTEMD_CFLAGS)
