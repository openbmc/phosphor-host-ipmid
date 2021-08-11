sensorutils_lib = static_library(
  'sensorutils',
  'sensorutils.cpp',
  implicit_include_directories: false,
)

sensorutils_dep = declare_dependency(
  link_with: sensorutils_lib,
)

dbus_sdr_pre = declare_dependency(
  include_directories: root_inc,
  dependencies: [
    crypto,
    phosphor_logging_dep,
    ipmid_dep,
    libipmi20_dep,
    sensorutils_dep,
  ],
)

dbus_sdr_src = [
  'sdrutils.cpp',
  'sensorcommands.cpp',
  'storagecommands.cpp',
]

shared_module(
  'dynamiccmds',
  dbus_sdr_src,
  implicit_include_directories: false,
  dependencies: dbus_sdr_pre,
  install: true,
  install_dir: get_option('libdir') / 'ipmid-providers',
)

