ipmid_pre = [
  sdbusplus_dep,
]

libipmid_host = library(
  'ipmid-host',
  dependencies: ipmid_pre,
  version: meson.project_version(),
  include_directories: root_inc,
  install: true,
  install_dir: get_option('libdir'))

ipmid_host_dep = declare_dependency(
  dependencies: ipmid_pre,
  include_directories: root_inc,
  link_with: libipmid_host)
