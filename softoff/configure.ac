# Initialization
AC_PREREQ([2.69])
AC_INIT([phosphor-host-ipmid], [1.0], [https://github.com/openbmc/phosphor-host-ipmid/issues])
AC_LANG([C++])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([subdir-objects -Wall -Werror foreign dist-xz])
AM_SILENT_RULES([yes])

# Checks for programs.
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_MKDIR_P
AC_CHECK_PROG([DIRNAME], dirname, dirname)

# Check for sdbusplus
AC_PATH_PROG([SDBUSPLUSPLUS], [sdbus++])
AS_IF([test "x$SDBUSPLUSPLUS" == "x"],
    AC_MSG_ERROR([Cannot find sdbus++]))

# Checks for typedefs, structures, and compiler characteristics.
AX_CXX_COMPILE_STDCXX_14([noext])
AX_APPEND_COMPILE_FLAGS([-Wall -Werror], [CXXFLAGS])

LT_INIT # Needed to link libtool to systemd

# Checks for modules.
AX_PKG_CHECK_MODULES([SYSTEMD], [], [libsystemd >= 221] , [], [AC_MSG_ERROR(["systemd package required and not found"])])

# Commenting until I solve the package not found error
# AX_PKG_CHECK_MODULES([SDBUSPLUS], [], [sdbusplus], [], [AC_MSG_ERROR(["sdbusplus package required and not found"])])
AC_CHECK_HEADER(sdbusplus/server.hpp, ,[AC_MSG_ERROR([Could not find sdbusplus/server.hpp...openbmc/sdbusplus package required])])

# Dbus service name
AC_ARG_VAR(BUSNAME, [The Dbus busname to own])
AS_IF([test "x$BUSNAME" == "x"], [BUSNAME="xyz.openbmc_project.Ipmi.SoftPowerOff"])
AC_DEFINE_UNQUOTED([BUSNAME], ["$BUSNAME"], [The Dbus busname to own])

# Service dbus root
AC_ARG_VAR(OBJPATH, [The SoftPowerOff Dbus root])
AS_IF([test "x$OBJPATH" == "x"], [OBJPATH="/xyz/openbmc_project/Ipmi/SoftPowerOff"])
AC_DEFINE_UNQUOTED([OBJPATH], ["$OBJPATH"], [The SoftPowerOff Dbus root])

# Create configured output
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
