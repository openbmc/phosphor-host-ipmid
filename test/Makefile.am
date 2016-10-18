check_PROGRAMS =

# Run all 'check' test programs
TESTS = $(check_PROGRAMS)

# Build/add sample_unittest to test suite
check_PROGRAMS += sample_unittest
sample_unittest_CPPFLAGS = -Igtest $(GTEST_CPPFLAGS)
sample_unittest_CXXFLAGS = $(PTHREAD_CFLAGS)
sample_unittest_LDFLAGS = -lgtest_main -lgtest $(PTHREAD_LIBS) $(OESDK_TESTCASE_FLAGS)
sample_unittest_SOURCES = sample_unittest.cpp
sample_unittest_LDADD = $(top_builddir)/sample.o

check_PROGRAMS += ipmid_unittest
ipmid_unittest_CPPFLAGS = -Igtest $(GTEST_CPPFLAGS)
ipmid_unittest_CXXFLAGS = $(PTHREAD_CFLAGS)
ipmid_unittest_LDFLAGS = -lgtest -lgmock -lglog $(PTHREAD_LIBS) $(OESDK_TESTCASE_FLAGS)
ipmid_unittest_SOURCES = \
	test-main.cpp \
	ipmid-test-utils.cpp \
	ipmid-router-test.cpp \
	dbus-test.cpp
ipmid_unittest_LDADD = \
	$(top_builddir)/ipmid-router.o \
	$(top_builddir)/dbus.o
