AM_CPPFLAGS = -I$(top_srcdir) $(GTEST_CFLAGS) -DUNITTEST
AM_CXXFLAGS = $(PTHREAD_CFLAGS) $(GTEST_CFLAGS)
AM_LDFLAGS = $(GTEST_LIBS) $(PTHREAD_LIBS) $(OESDK_TESTCASE_FLAGS)

# Run all 'check' test programs
check_PROGRAMS =
TESTS = $(check_PROGRAMS)

# Build/add sample_unittest to test suite
check_PROGRAMS += sample_unittest
sample_unittest_SOURCES = sample_unittest.cpp
sample_unittest_LDADD = $(top_builddir)/sample.o

check_PROGRAMS += sensorhandler_unittest
sensorhandler_unittest_LDFLAGS = $(SDBUSPLUS_LIBS) $(AM_LDFLAGS)
sensorhandler_unittest_SOURCES = sensorhandler_unittest.cpp
sensorhandler_unittest_LDADD = $(top_builddir)/sensorhandler.o
