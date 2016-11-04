AM_CPPFLAGS = -I$(top_srcdir)
check_PROGRAMS =

# Run all 'check' test programs
TESTS = $(check_PROGRAMS)

# Build/add sample_unittest to test suite
check_PROGRAMS += sample_unittest
sample_unittest_CPPFLAGS = -Igtest $(GTEST_CPPFLAGS) $(AM_CPPFLAGS)
sample_unittest_CXXFLAGS = $(PTHREAD_CFLAGS)
sample_unittest_LDFLAGS = -lgtest_main -lgtest $(PTHREAD_LIBS) $(OESDK_TESTCASE_FLAGS)
sample_unittest_SOURCES = sample_unittest.cpp
sample_unittest_LDADD = $(top_builddir)/sample.o
