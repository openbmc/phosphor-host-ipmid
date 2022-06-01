sensorutils_lib = static_library(
  'sensorutils',
  'sensorutils.cpp',
  include_directories: root_inc,
  implicit_include_directories: false)

sensorutils_dep = declare_dependency(link_with: sensorutils_lib)

dbus_sdr_pre = declare_dependency(
  include_directories: root_inc,
  dependencies: [
    crypto,
    phosphor_logging_dep,
    ipmid_dep,
    libipmi20_dep,
    sensorutils_dep,
  ])

dbus_sdr_src = [
  'dbus-sdr/sdrutils.cpp',
  'dbus-sdr/sensorcommands.cpp',
  'dbus-sdr/storagecommands.cpp'
]
