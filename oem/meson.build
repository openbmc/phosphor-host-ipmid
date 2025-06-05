oem_opt = get_option('oem-libraries')

ipmi_plugin_options = ['b_lundef=false']

#################################################
# keep options below sorted alphabetically
#################################################
if 'example' in oem_opt or 'all' in oem_opt
    subdir('example')
endif

if 'nvidia' in oem_opt or 'all' in oem_opt
    subdir('nvidia')
endif
