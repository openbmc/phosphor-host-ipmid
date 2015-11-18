ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = ipmid

ipmid_SOURCES = ipmid.C ipmid.H
ipmid_LDADD = host-ipmid/libapphandler.la
ipmid_CXXFLAGS = -DHOST_IPMI_LIB_PATH=\"/usr/lib/host-ipmid/\"
ipmid_LDFLAGS = $(libsystemd_LIBS) $(LIBADD_DLOPEN)

nobase_lib_LTLIBRARIES = host-ipmid/libapphandler.la
nobase_include_HEADERS = host-ipmid/ipmid-api.h
host_ipmid_libapphandler_la_SOURCES = apphandler.C apphandler.h \
              sensorhandler.C sensorhandler.h \
              storagehandler.C storagehandler.h \
              chassishandler.C chassishandler.h \
              dcmihandler.C dcmihandler.h \
              ipmisensor.C \
              storageaddsel.C storageaddsel.h  \
              transporthandler.C transporthandler.h

host_ipmid_libapphandler_la_CXXFLAGS = $(libsystemd_CFLAGS)
host_ipmid_libapphandler_la_LDFLAGS = -version-info 0:0:0 $(libsystemd_LIBS)

check_PROGRAMS = testit
TESTS = $(check_PROGRAMS)

testit_SOURCES = testit.C
testit_LDFLAGS = $(libsystemd_LIBS) $(LIBADD_DLOPEN)
