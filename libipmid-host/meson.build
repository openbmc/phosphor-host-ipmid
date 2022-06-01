ipmid_pre = [
  sdbusplus_dep,
]

library(
  'ipmid-host',
  dependencies: ipmid_pre,
  version: meson.project_version(),
  include_directories: root_inc,
  install: true,
  install_dir: get_option('libdir'))
