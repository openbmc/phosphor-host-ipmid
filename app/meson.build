app_inc = include_directories('.')

app_pre = declare_dependency(include_directories: [root_inc, app_inc])

app_lib = static_library(
  'app',
  'channel.cpp',
  'watchdog.cpp',
  'watchdog_service.cpp',
  implicit_include_directories: false,
  dependencies: app_pre)

app_dep = declare_dependency(
  link_with: app_lib,
  dependencies: app_pre)
