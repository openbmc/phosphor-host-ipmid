AM_CPPFLAGS = -I$(top_srcdir) $(GTEST_CFLAGS)
AM_CXXFLAGS = $(GTEST_MAIN_CFLAGS) $(GTEST_CFLAGS)
AM_LDFLAGS = $(GTEST_MAIN_LIBS) $(OESDK_TESTCASE_FLAGS)

# Run all 'check' test programs
check_PROGRAMS =
TESTS = $(check_PROGRAMS)

# Build/add sample_unittest to test suite
check_PROGRAMS += sample_unittest
sample_unittest_SOURCES = sample_unittest.cpp
sample_unittest_LDADD = $(top_builddir)/sample.o

# Build/add oemrouter_unittest to test suite
check_PROGRAMS += oemrouter_unittest
oemrouter_unittest_SOURCES = oemrouter_unittest.cpp
oemrouter_unittest_LDADD = $(top_builddir)/oemrouter.o
