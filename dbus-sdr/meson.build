dbus_sdr_pre = declare_dependency(
  include_directories: [root_inc],
  dependencies: [
    crypto,
    ipmid_main_dep,
    phosphor_logging_dep,
    libipmi20_dep,
  ],
)

dbus_sdr_src = [
  'sdrutils.cpp',
  'sensorutils.cpp',
  'sensorcommands.cpp',
  'storagecommands.cpp',
]

dbus_sdr_lib = library(
  'dynamiccmds',
  dbus_sdr_src,
  implicit_include_directories: false,
  dependencies: dbus_sdr_pre,
  version: meson.project_version(),
  install: true,
  install_dir: get_option('libdir') / 'ipmid-providers',
)

dbus_sdr_dep = declare_dependency(
  link_with: dbus_sdr_lib,
  dependencies: dbus_sdr_pre,
)
