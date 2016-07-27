# Initialization
AC_PREREQ([2.69])
AC_INIT([phosphor-host-ipmid], [1.0], [https://github.com/openbmc/phosphor-host-ipmid/issues])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([subdir-objects -Wall -Werror foreign dist-xz])
AM_PROG_AR()

# Checks for programs.
AC_PROG_CXX
AX_CXX_COMPILE_STDCXX(14, [noext])
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for libraries.
AC_CHECK_LIB([mapper], [mapper_get_service])
PKG_CHECK_MODULES([SYSTEMD], [libsystemd >= 221])

# Checks for header files.
AC_CHECK_HEADER(systemd/sd-bus.h, ,[AC_MSG_ERROR([Could not find systemd/sd-bus.h...systemd developement package required])])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
LT_INIT
LT_LIB_DLLOAD
AC_ENABLE_SHARED
AC_DISABLE_STATIC

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
