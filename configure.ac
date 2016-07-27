# Initialization
AC_PREREQ([2.69])
AC_INIT([phosphor-host-ipmid], [1.0], [https://github.com/openbmc/phosphor-host-ipmid/issues])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CXX
AX_CXX_COMPILE_STDCXX(14)
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for libraries.
AC_CHECK_LIB([dl], [dlopen])
PKG_CHECK_MODULES([SYSTEMD], [libsystemd])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h limits.h malloc.h stdint.h stdlib.h string.h sys/time.h unistd.h])
AC_CHECK_HEADER(systemd/sd-bus.h, ,[AC_MSG_ERROR([Could not find systemd/sd-bus.h...systemd developement package required])])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_INT16_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
LT_INIT
AC_ENABLE_SHARED
AC_DISABLE_STATIC
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strdup strerror strrchr strstr strtol strtoul])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
