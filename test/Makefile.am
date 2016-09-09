check_PROGRAMS = 

TESTS = $(check_PROGRAMS)

#Execute test program command
#LD_LIBRARY_PATH=/home/msbarth/OpenBMC/sdk/sysroots/core2-64-openbmc-linux/lib:/home/msbarth/OpenBMC/sdk/sysroots/core2-64-openbmc-linux/usr/lib /home/msbarth/OpenBMC/sdk/sysroots/core2-64-openbmc-linux/lib/ld-2.23.so ./sample_unittest

#Possible solution needing to be converted for automake
#$ ${CXX} -I ../.. -O3 read.cpp --std=c++14 -lpthread -lsystemd -Wl,-dynamic-linker,/home/iawillia/sdk/sysroots/core2-64-openbmc-linux/lib/ld-2.23.so
#
#LD_LIBRARY_PATH=/home/iawillia/sdk/sysroots/core2-64-openbmc-linux/lib:/home/iawillia/sdk/sysroots/core2-64-openbmc-linux/usr/lib ./a.out

#Build/add sample_unittest to test suite
check_PROGRAMS += sample_unittest
sample_unittest_CPPFLAGS = -Igtest $(GTEST_CPPFLAGS)
#	$(AM_CPPFLAGS)
sample_unittest_CXXFLAGS = $(PTHREAD_CFLAGS)
#	$(AM_CXXFLAGS)
sample_unittest_LDFLAGS = -lgtest_main -lgtest $(PTHREAD_LIBS)
#	$(AM_LDFLAGS)
sample_unittest_SOURCES = sample_unittest.cpp
sample_unittest_LDADD = $(top_builddir)/sample.o
