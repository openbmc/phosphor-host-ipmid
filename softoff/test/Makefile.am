AM_CPPFLAGS = -I$(top_srcdir)/softoff

# Run all 'check' test programs
TESTS = $(check_PROGRAMS)

# # Build/add utest to test suite
check_PROGRAMS = utest
utest_CPPFLAGS = -Igtest $(GTEST_CPPFLAGS) $(AM_CPPFLAGS)
utest_CXXFLAGS = $(PTHREAD_CFLAGS)
utest_LDFLAGS = -lgtest_main -lgtest $(PTHREAD_LIBS) $(OESDK_TESTCASE_FLAGS) $(SYSTEMD_LIBS) ${SDBUSPLUS_LIBS}
utest_SOURCES = utest.cpp
utest_LDADD = $(top_builddir)/softoff/timer.o
