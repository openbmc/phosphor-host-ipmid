project(
  'phosphor-host-ipmid',
  'cpp',
  version: '0.1',
  meson_version: '>=1.1.1',
  default_options: [
    'werror=true',
    'warning_level=3',
    'cpp_std=c++23',
    'b_lto=true',
  ])

# Setting up config data
conf_data = configuration_data()

# The name of the callout's forward association
conf_data.set_quoted('CALLOUT_FWD_ASSOCIATION', 'callout')
conf_data.set_quoted('BOARD_SENSOR', get_option('board-sensor'))
conf_data.set_quoted('SYSTEM_SENSOR', get_option('system-sensor'))
conf_data.set('IPMI_SMS_ATN_ACK_TIMEOUT_SECS', get_option('ipmi-sms-atn-ack-timeout-secs'))

# Soft Power off related.
if not get_option('softoff').disabled()
  conf_data.set_quoted('SOFTOFF_BUSNAME', get_option('softoff-busname'))
  conf_data.set_quoted('SOFTOFF_OBJPATH', get_option('softoff-objpath'))
  conf_data.set('IPMI_HOST_SHUTDOWN_COMPLETE_TIMEOUT_SECS', get_option('ipmi-host-shutdown-complete-timeout-secs'))
  conf_data.set_quoted('HOST_INBAND_REQUEST_DIR', get_option('host-inband-request-dir'))
  conf_data.set_quoted('HOST_INBAND_REQUEST_FILE', get_option('host-inband-request-file'))
endif

conf_data.set_quoted('CONTROL_HOST_BUSNAME', get_option('control-host-busname'))
conf_data.set_quoted('CONTROL_HOST_OBJ_MGR', get_option('control-host-obj-mgr'))
conf_data.set_quoted('HOST_NAME', get_option('host-name'))
conf_data.set_quoted('POWER_READING_SENSOR', get_option('power-reading-sensor'))
conf_data.set_quoted('HOST_IPMI_LIB_PATH', get_option('host-ipmi-lib-path'))
conf_data.set_quoted('FW_VER_REGEX', get_option('fw-ver-regex'))

if get_option('shortname-remove-suffix').allowed()
  conf_data.set_quoted('SHORTNAME_REMOVE_SUFFIX', '1')
endif
if get_option('shortname-replace-words').allowed()
  conf_data.set_quoted('SHORTNAME_REPLACE_WORDS', '1')
endif
if get_option('open-power').allowed()
  conf_data.set_quoted('OPEN_POWER_SUPPORT', '1')
endif

matches_map = get_option('matches-map')
conf_data.set('MAJOR_MATCH_INDEX', matches_map[0])
conf_data.set('MINOR_MATCH_INDEX', matches_map[1])
conf_data.set('AUX_0_MATCH_INDEX', matches_map[2])
conf_data.set('AUX_1_MATCH_INDEX', matches_map[3])
conf_data.set('AUX_2_MATCH_INDEX', matches_map[4])
conf_data.set('AUX_3_MATCH_INDEX', matches_map[5])

conf_h = configure_file(
  output: 'config.h',
  configuration: conf_data)

root = meson.current_source_dir()
root_inc = include_directories('.', 'include')

# Project Arguments
cpp = meson.get_compiler('cpp')
add_project_arguments(
  cpp.get_supported_arguments([
    '-DBOOST_ERROR_CODE_HEADER_ONLY',
    '-DBOOST_SYSTEM_NO_DEPRECATED',
    '-DBOOST_COROUTINES_NO_DEPRECATION_WARNING',
    '-DBOOST_ASIO_DISABLE_THREADS',
    '-DBOOST_ALL_NO_LIB',
  ]),
  language : 'cpp')

if not get_option('get-dbus-active-software').disabled()
  add_project_arguments(
    cpp.get_supported_arguments([
      '-DGET_DBUS_ACTIVE_SOFTWARE',
    ]),
    language : 'cpp')
endif

feature_map = {
  'boot-flag-safe-mode-support': '-DENABLE_BOOT_FLAG_SAFE_MODE_SUPPORT',
  'i2c-whitelist-check'        : '-DENABLE_I2C_WHITELIST_CHECK',
  'update-functional-on-fail'  : '-DUPDATE_FUNCTIONAL_ON_FAIL',
  'dynamic-sensors'            : '-DFEATURE_DYNAMIC_SENSORS',
  'dynamic-sensors-write'      : '-DFEATURE_DYNAMIC_SENSORS_WRITE',
  'entity-manager-decorators'  : '-DUSING_ENTITY_MANAGER_DECORATORS',
  'hybrid-sensors'             : '-DFEATURE_HYBRID_SENSORS',
  'sensors-cache'              : '-DFEATURE_SENSORS_CACHE',
  'dynamic-storages-only'      : '-DFEATURE_DYNAMIC_STORAGES_ONLY',
}

foreach option_key, option_value : feature_map
  if(get_option(option_key).allowed())
    summary(option_key,option_value, section : 'Enabled Features')
    add_project_arguments(option_value,language:'cpp')
  endif
endforeach

add_project_arguments(
  cpp.get_supported_arguments([
    '-Wno-psabi',
    '-Wno-missing-field-initializers',
    '-Wno-pedantic',
    '-Wno-non-virtual-dtor'
  ]),
  language: 'cpp')

# Dependencies

boost = dependency(
  'boost',
  modules: [
    'coroutine',
  ],
  required : false,
)

if not boost.found()
  cmake = import('cmake')
  opt = cmake.subproject_options()
  opt.add_cmake_defines({
    'BOOST_INCLUDE_LIBRARIES': 'asio;bimap;callable_traits;context;coroutine;interprocess;multiprecision;process',
    'CMAKE_POSITION_INDEPENDENT_CODE': true
  })
  boost_cmake = cmake.subproject('boost', required: true, options: opt)
  boost_asio = boost_cmake.dependency('boost_asio').as_system()
  boost_bimap = boost_cmake.dependency('boost_bimap').as_system()
  boost_callable_traits = boost_cmake.dependency('boost_callable_traits').as_system()
  boost_context = boost_cmake.dependency('boost_context').as_system()
  boost_coroutine = boost_cmake.dependency('boost_coroutine').as_system()
  boost_interprocess = boost_cmake.dependency('boost_interprocess').as_system()
  boost_multiprecision = boost_cmake.dependency('boost_multiprecision').as_system()
  boost_process = boost_cmake.dependency('boost_process').as_system()
  boost = [boost_asio, boost_bimap, boost_callable_traits, boost_context, boost_coroutine, boost_interprocess, boost_multiprecision, boost_process]
endif

phosphor_logging_dep = dependency('phosphor-logging')
phosphor_dbus_interfaces_dep = dependency('phosphor-dbus-interfaces')
sdeventplus_dep = dependency('sdeventplus')
libsystemd_dep = dependency('libsystemd')
crypto = dependency('libcrypto', version : '>=1.0.2g')
pam = cpp.find_library('pam', required: true)
sdbusplus_dep = dependency('sdbusplus')
stdplus_dep = dependency('stdplus')

nlohmann_json_dep = dependency('nlohmann_json', include_type: 'system')

generated_src = []

# Subfolders
subdir('libipmid')
subdir('include')
subdir('user_channel')
subdir('scripts')

if not get_option('softoff').disabled()
  subdir('xyz/openbmc_project/Ipmi/Internal/SoftPowerOff')
  subdir('softoff')
endif

# whitelist
if not get_option('ipmi-whitelist').disabled()
  generate_whitelist_script = files('generate_whitelist_create.sh')

  whitelist_conf = get_option('whitelist-conf')
  ipmiwhitelist = run_command( \
    'bash', \
    generate_whitelist_script, \
    whitelist_conf)

  whitelist_pre = declare_dependency(
    include_directories: root_inc,
    dependencies: [
      crypto,
      ipmid_dep,
      phosphor_dbus_interfaces_dep,
      phosphor_logging_dep,
      sdbusplus_dep,
    ],
  )

  whitelist_lib = library(
    'whitelist',
    'whitelist-filter.cpp',
    'ipmiwhitelist.cpp',
    implicit_include_directories: false,
    dependencies: whitelist_pre,
    version: meson.project_version(),
    override_options: ['b_lundef=false'],
    install: true,
    install_dir: get_option('libdir') / 'ipmid-providers')
endif

# libsysintfcmds
sysintfcmds_pre = declare_dependency(
  include_directories: root_inc,
  dependencies: [
    channellayer_dep,
    crypto,
    nlohmann_json_dep,
    phosphor_dbus_interfaces_dep,
    phosphor_logging_dep,
    sdbusplus_dep,
    ipmid_dep,
  ])

sysintfcmds_lib = library(
  'sysintfcmds',
  'systemintfcmds.cpp',
  'host-interface.cpp',
  implicit_include_directories: false,
  dependencies: sysintfcmds_pre,
  version: meson.project_version(),
  override_options: ['b_lundef=false'],
  install: true,
  install_dir: get_option('libdir') / 'ipmid-providers')

# ipmid
ipmid_pre = [
  sdbusplus_dep,
  stdplus_dep,
  phosphor_logging_dep,
  phosphor_dbus_interfaces_dep,
  boost,
  crypto,
  ipmid_dep,
  channellayer_dep,
]

transportoem_src = []
if not get_option('transport-oem').disabled()
  transportoem_src = ['transporthandler_oem.cpp']
endif

storage_cmds_src = []
if get_option('dynamic-sensors').disabled() and not get_option('dynamic-storages-only').disabled()
  storage_cmds_src = ['dbus-sdr/storagecommands.cpp', 'dbus-sdr/sdrutils.cpp']
endif

openpower_cmds_src = []
if get_option('open-power').allowed()
  openpower_cmds_src = [ 'storageaddsel.cpp' ]
endif

libipmi20_src = [
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
  'transporthandler.cpp',
  'globalhandler.cpp',
  'groupext.cpp',
  'selutility.cpp',
  'ipmi_fru_info_area.cpp',
  'read_fru_data.cpp',
  'sensordatahandler.cpp',
  'user_channel/channelcommands.cpp',
  generated_src,
  transportoem_src,
  storage_cmds_src,
  openpower_cmds_src,
  conf_h,
]

ipmi20_lib = library(
  'ipmi20',
  libipmi20_src,
  dependencies: [ipmid_pre, nlohmann_json_dep],
  include_directories: root_inc,
  install: true,
  install_dir: get_option('libdir') / 'ipmid-providers',
  version: meson.project_version(),
  override_options: ['b_lundef=false'])

libipmi20_dep = declare_dependency(
  dependencies: ipmid_pre,
  include_directories: root_inc,
  link_with: ipmi20_lib)

# ipmid binary
executable(
  'ipmid',
  'ipmid-new.cpp',
  'host-cmd-manager.cpp',
  'settings.cpp',
  implicit_include_directories: false,
  dependencies: [libipmi20_dep],
  include_directories: root_inc,
  export_dynamic: true,
  install: true,
  install_dir: get_option('bindir'))

# Dynamic Sensor Stack
subdir('dbus-sdr')

if not get_option('dynamic-sensors').disabled() or not get_option('tests').disabled()
  library(
    'dynamiccmds',
    dbus_sdr_src,
    implicit_include_directories: false,
    dependencies: dbus_sdr_pre,
    version: meson.project_version(),
    override_options: ['b_lundef=false'],
    install: true,
    install_dir: get_option('libdir') / 'ipmid-providers')
endif

if not get_option('tests').disabled()
  subdir('test')
endif

install_subdir(
  'user_channel',
  install_dir: get_option('includedir'),
  strip_directory: false,
  exclude_files: '*.cpp')
