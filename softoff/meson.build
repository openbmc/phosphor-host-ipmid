softpower_pre = [
  ipmid_dep,
  phosphor_logging_dep,
  phosphor_dbus_interfaces_dep,
  sdeventplus_dep,
  sdbusplus_dep,
  systemd,
  softoff_dbus,
  boost_coroutine
]

softpower_lib = static_library(
  'softpower_lib',
  'softoff.cpp',
  conf_h,
  dependencies: softpower_pre,
  include_directories: root_inc)

softpower_dep = declare_dependency(
  dependencies: softpower_pre,
  include_directories: root_inc,
  link_with: softpower_lib)

executable(
  'phosphor-softpoweroff',
  'mainapp.cpp',
  implicit_include_directories: false,
  dependencies: softpower_dep,
  include_directories: root_inc,
  install: true,
  install_dir: get_option('bindir'))
