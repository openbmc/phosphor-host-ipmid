user_channel_inc = include_directories('.')

channellayer_pre = declare_dependency(
  include_directories: [root_inc, user_channel_inc],
  dependencies: [
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

channellayer_lib = static_library(
  'channellayer_lib',
  channellayer_src,
  implicit_include_directories: false,
  dependencies: channellayer_pre,
)

channellayer_dep = declare_dependency(
  link_with: channellayer_lib,
  dependencies: channellayer_pre,
)

shared_module(
  'channellayer',
  implicit_include_directories: false,
  sources: channellayer_src,
  dependencies: [
    channellayer_dep,
  ],
  install: true,
  install_dir: get_option('libdir'),
)

userlayer_pre = declare_dependency(
  include_directories: [root_inc, user_channel_inc],
  dependencies: [
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

userlayer_lib = static_library(
  'userlayer_lib',
  userlayer_src,
  implicit_include_directories: false,
  dependencies: userlayer_pre,
)

userlayer_dep = declare_dependency(
  link_with: userlayer_lib,
  dependencies: userlayer_pre,
)

shared_module(
  'userlayer',
  implicit_include_directories: false,
  sources: userlayer_src,
  dependencies: [
    userlayer_dep,
  ],
  install: true,
  install_dir: get_option('libdir'),
)

usercmds_pre = declare_dependency(
  include_directories: [root_inc, user_channel_inc],
  dependencies: [
    mapper,
    phosphor_logging_dep,
    ipmid_dep,
    userlayer_dep,
    channellayer_dep,
  ],
)

usercmds_lib = static_library(
  'usercmds_lib',
  'usercommands.cpp',
  implicit_include_directories: false,
  dependencies: usercmds_pre,
)

usercmds_dep = declare_dependency(
  link_with: usercmds_lib,
  dependencies: usercmds_pre,
)

shared_module(
  'usercmds',
  implicit_include_directories: false,
  sources: ['usercommands.cpp'],
  dependencies: [
    usercmds_dep,
  ],
  install: true,
  install_dir: get_option('libdir') / 'ipmid-providers',
)
