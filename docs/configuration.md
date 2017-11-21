#Device ID Configuration#

There is a default dev_id.json file provided by
meta-phosphor/common/recipes-phosphor/ipmi/phosphor-ipmi-host.bb

Any target can override the default json file by providing a phosphor-ipmi-host.bbappend with an ODM
or platform customizable configuration.

For a specific example, see:
[Witherspoon](https://github.com/openbmc/openbmc/blob/master/meta-openbmc-machines/
meta-openpower/meta-ibm/meta-witherspoon/recipes-phosphor/ipmi/phosphor-ipmi-host.bbappend)

The JSON format for get_device_id:

    {"id": 0, "revision": 0, "addn_dev_support": 0, "manuf_id": 0, "prod_id": 0, "aux": 0}

You can change the data for your platform as an integer. When this file is placed in
/usr/share/ipmi-providers/ it will be parsed when this service is initially run
and the data is cached.
