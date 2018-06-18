AM_CPPFLAGS = -I$(top_srcdir) $(CODE_COVERAGE_CPPFLAGS)
AM_CFLAGS = $(CODE_COVERAGE_CFLAGS)
check_PROGRAMS =

# Run all 'check' test programs
TESTS = $(check_PROGRAMS)

# Build/add sample_unittest to test suite
sample_unittest_CPPFLAGS = -Igtest $(GTEST_CPPFLAGS) $(AM_CPPFLAGS)
sample_unittest_CXXFLAGS = $(PTHREAD_CFLAGS) $(CODE_COVERAGE_CXXFLAGS) \
			   $(CODE_COVERAGE_CFLAGS)
sample_unittest_LDFLAGS = -lgtest_main -lgtest $(PTHREAD_LIBS) $(OESDK_TESTCASE_FLAGS) \
   			$(CODE_COVERAGE_LDFLAGS)
sample_unittest_SOURCES = %reldir%/sample_unittest.cpp
sample_unittest_LDADD = $(top_builddir)/sample.o
check_PROGRAMS += %reldir%/sample_unittest
