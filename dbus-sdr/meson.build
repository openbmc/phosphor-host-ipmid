dbus_sdr_pre = declare_dependency(
  include_directories: [root_inc],
  dependencies: [
    phosphor_logging_dep,
  ],
)

dbus_sdr_lib = static_library(
  'dbus-sdr',
  'sdrutils.cpp',
  'sensorutils.cpp',
  implicit_include_directories: false,
  dependencies: dbus_sdr_pre,
)

dbus_sdr_dep = declare_dependency(
  link_with: dbus_sdr_lib,
  dependencies: dbus_sdr_pre,
)

shared_module(
  'dynamiccmds',
  'sensorcommands.cpp',
  'sensorutils.cpp',
  implicit_include_directories: false,
  dependencies: [
    dbus_sdr_dep,
  ],
  install: true,
  install_dir: get_option('libdir') / 'ipmid-providers',
)
