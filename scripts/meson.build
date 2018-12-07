python2 = import('python').find_installation('python2')

sensor_gen_cxx = custom_target(
  'sensor-gen',
  input: files(get_option('sensor-yaml')),
  output: ['sensor-gen.cpp'],
  command: [
    python2,
    files('sensor_gen.py'),
    '-i', '@INPUT@',
    '-o', '@OUTDIR@',
    'generate-cpp',
  ])

inventory_sensor_gen_cxx = custom_target(
  'inventory-sensor-gen',
  input: files(get_option('inventory-sensor-yaml')),
  output: ['inventory-sensor-gen.cpp'],
  command: [
    python2,
    files('inventory-sensor.py'),
    '-i', '@INPUT@',
    '-o', '@OUTDIR@',
    'generate-cpp',
  ])

fru_read_gen_cxx = custom_target(
  'fru-read-gen',
  input: files(get_option('fru-read-yaml')),
  output: ['fru-read-gen.cpp'],
  command: [
    python2,
    files('fru_gen.py'),
    '-i', '@INPUT@',
    '-o', '@OUTDIR@',
    'generate-cpp',
  ])

channel_gen_cxx = custom_target(
  'channel-gen',
  input: files(get_option('channel-yaml')),
  output: ['channel-gen.cpp'],
  command: [
    python2,
    files('channel_gen.py'),
    '-i', '@INPUT@',
    '-o', '@OUTDIR@',
    'generate-cpp',
  ])
