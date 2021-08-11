user_channel_inc = include_directories('.')

channellayer_pre = declare_dependency(
  include_directories: [root_inc, user_channel_inc],
  dependencies: [
    crypto,
    ipmid_main_dep,
    ipmid_dep,
    phosphor_dbus_interfaces_dep,
    phosphor_logging_dep,
    std_cpp_fs,
    systemd,
  ],
)

channellayer_src = [
  'channel_layer.cpp',
  'channel_mgmt.cpp',
  'cipher_mgmt.cpp',
]

channellayer_lib = library(
  'channellayer',
  channellayer_src,
  implicit_include_directories: false,
  dependencies: channellayer_pre,
  version: meson.project_version(),
  install: true,
  install_dir: get_option('libdir'),
)

channellayer_dep = declare_dependency(
  link_with: channellayer_lib,
  dependencies: channellayer_pre,
)

if not get_option('libuserlayer').disabled()

userlayer_pre = declare_dependency(
  include_directories: [root_inc, user_channel_inc],
  dependencies: [
    ipmid_main_dep,
    channellayer_dep,
    crypto,
    ipmid_dep,
    phosphor_dbus_interfaces_dep,
    phosphor_logging_dep,
    pam,
    std_cpp_fs,
    systemd,
  ],
)

userlayer_src = [
  'user_layer.cpp',
  'user_mgmt.cpp',
  'passwd_mgr.cpp',
]

userlayer_lib = library(
  'userlayer',
  userlayer_src,
  implicit_include_directories: false,
  dependencies: userlayer_pre,
  version: meson.project_version(),
  install: true,
  install_dir: get_option('libdir'),
)

userlayer_dep = declare_dependency(
  link_with: userlayer_lib,
  dependencies: userlayer_pre,
)

usercmds_pre = declare_dependency(
  include_directories: [root_inc, user_channel_inc],
  dependencies: [
    ipmid_main_dep,
    mapper,
    phosphor_logging_dep,
    ipmid_dep,
    userlayer_dep,
    channellayer_dep,
  ],
)

usercmds_lib = library(
  'usercmds',
  'usercommands.cpp',
  implicit_include_directories: false,
  dependencies: usercmds_pre,
  version: meson.project_version(),
  install: true,
  install_dir: get_option('libdir') / 'ipmid-providers',
)

usercmds_dep = declare_dependency(
  link_with: usercmds_lib,
  dependencies: usercmds_pre,
)

endif
