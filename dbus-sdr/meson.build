dbus_sdr_pre = declare_dependency(
  include_directories: [root_inc],
  dependencies: [
    crypto,
    phosphor_logging_dep,
    libipmi20_dep,
  ],
)

dbus_sdr_src = [
  'sdrutils.cpp',
  'sensorutils.cpp',
  'sensorcommands.cpp',
  'sensorutils.cpp',
]

dbus_sdr_lib = static_library(
  'dbus_sdr_lib',
  dbus_sdr_src,
  implicit_include_directories: false,
  dependencies: dbus_sdr_pre,
)

dbus_sdr_dep = declare_dependency(
  link_with: dbus_sdr_lib,
  dependencies: dbus_sdr_pre,
)

shared_module(
  'dynamiccmds',
  dbus_sdr_src,
  implicit_include_directories: false,
  dependencies: [
    dbus_sdr_dep,
  ],
  install: true,
  install_dir: get_option('libdir') / 'ipmid-providers',
)
