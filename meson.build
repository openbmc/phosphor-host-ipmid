project('phosphor-host-ipmid', 'cpp',
        version: '1.0',
        default_options: [
          'cpp_std=c++17',
          'b_lundef=false',
          'b_lto=true',
        ])
add_project_arguments('-Wall', '-Werror', language: 'cpp')

includes = include_directories('.')

build_tests = get_option('tests')
build_examples = get_option('examples')

boost_defines = [
  '-DBOOST_ERROR_CODE_HEADER_ONLY',
  '-DBOOST_SYSTEM_NO_DEPRECATED',
  '-DBOOST_ALL_NO_LIB',
]
add_project_arguments(boost_defines, language: 'cpp')

ipmid_providers_dir = join_paths(
  get_option('libdir'), get_option('install-provider-path'))

cxx = meson.get_compiler('cpp')
threads = dependency('threads')
libdl = cxx.find_library('dl')
libmapper = cxx.find_library('mapper')
libsystemd = dependency('libsystemd')
phosphor_logging = dependency('phosphor-logging')
phosphor_dbus_interfaces = dependency('phosphor-dbus-interfaces')
sdbusplus = dependency('sdbusplus')

subdir('scripts')
subdir('host-ipmid')

ipmiwhitelist_cxx = custom_target(
  'ipmiwhitelist-gen',
  input: files(get_option('whitelist-confs')),
  output: ['ipmiwhitelist.cpp'],
  capture: true,
  command: [
    find_program('bash', native: true),
    files('generate_whitelist.sh'),
    '@INPUT@',
  ])

config = configuration_data()

config.set_quoted('HOST_IPMI_LIB_PATH', join_paths(
  get_option('prefix'), get_option('libdir'), get_option('load-provider-path')))
config.set_quoted('POWER_READING_SENSOR', join_paths(
  get_option('prefix'), get_option('datadir'), get_option('power-reading-config')))
config.set_quoted('CALLOUT_FWD_ASSOCIATION', 'callout')
config.set_quoted('BOARD_SENSOR',
                  '/xyz/openbmc_project/inventory/system/chassis/motherboard')
config.set_quoted('SYSTEM_SENSOR', '/xyz/openbmc_project/inventory/system')
config.set_quoted('HOST_NAME', get_option('host-name'))
config.set_quoted('CONTROL_HOST_BUSNAME', get_option('control-host-busname'))
config.set_quoted('CONTROL_HOST_OBJ_MGR', get_option('control-host-objpath'))
config.set_quoted('HOST_INBAND_REQUEST_DIR', get_option('host-inband-dir'))
config.set_quoted('HOST_INBAND_REQUEST_FILE', get_option('host-inband-file'))
config.set('IPMI_SMS_ATN_ACK_TIMEOUT_SECS',
           get_option('sms-atn-ack-timeout-sec'))
config.set('IPMI_HOST_SHUTDOWN_COMPLETE_TIMEOUT_SECS',
           get_option('host-shutdown-complete-timeout-sec'))
config.set_quoted('SOFTOFF_BUSNAME', get_option('softoff-busname'))
config.set_quoted('SOFTOFF_OBJPATH', get_option('softoff-objpath'))

configure_file(
  configuration: config,
  output: 'config.h')

utils = static_library(
  'utils',
  'utils.cpp',
  include_directories: includes,
  implicit_include_directories: false,
  dependencies: [
    phosphor_dbus_interfaces,
    phosphor_logging,
    sdbusplus,
  ])

library(
  'ipmi20',
  [
    'net.cpp',
    'app/channel.cpp',
    'app/watchdog.cpp',
    'app/watchdog_service.cpp',
    'apphandler.cpp',
    'sys_info_param.cpp',
    'sensorhandler.cpp',
    'storagehandler.cpp',
    'chassishandler.cpp',
    'dcmihandler.cpp',
    'ipmisensor.cpp',
    'storageaddsel.cpp',
    'transporthandler.cpp',
    'globalhandler.cpp',
    'groupext.cpp',
    'selutility.cpp',
    'ipmi_fru_info_area.cpp',
    'read_fru_data.cpp',
    'sensordatahandler.cpp',

    sensor_gen_cxx,
    inventory_sensor_gen_cxx,
    fru_read_gen_cxx,
    channel_gen_cxx,
  ],
  include_directories: includes,
  implicit_include_directories: false,
  link_with: utils,
  dependencies: [
    libmapper,
    libsystemd,
    phosphor_dbus_interfaces,
    phosphor_logging,
    sdbusplus,
  ],
  install_dir: ipmid_providers_dir,
  install: true)

library(
  'sysintfcmds',
  [
    'systemintfcmds.cpp',
    'host-interface.cpp',
  ],
  include_directories: includes,
  implicit_include_directories: false,
  dependencies: [
    phosphor_dbus_interfaces,
    phosphor_logging,
  ],
  install_dir: ipmid_providers_dir,
  install: true)

executable(
  'ipmid',
  [
    'ipmid.cpp',
    'settings.cpp',
    'host-cmd-manager.cpp',
    'oemrouter.cpp',
    ipmiwhitelist_cxx,
  ],
  include_directories: includes,
  implicit_include_directories: false,
  link_with: utils,
  dependencies: [
    libdl,
    libsystemd,
    phosphor_dbus_interfaces,
    phosphor_logging,
    sdbusplus,
    threads,
  ],
  export_dynamic: true,
  install: true)

subdir('user_channel')
subdir('xyz/openbmc_project/Ipmi/Internal/SoftPowerOff')
subdir('softoff')
if build_tests != 'false'
  if build_examples
    sample = static_library(
      'sample',
      'sample.cpp',
      include_directories: includes,
      implicit_include_directories: false)
  endif
  subdir('test')
endif
