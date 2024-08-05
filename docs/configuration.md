# Configuration

## Device ID Configuration

There is a default dev_id.json file provided by
meta-phosphor/common/recipes-phosphor/ipmi/phosphor-ipmi-host.bb

Any target can override the default json file by providing a
phosphor-ipmi-host.bbappend with an ODM or platform customizable configuration.

For a specific example, see:
[Witherspoon](https://github.com/openbmc/openbmc/blob/master/meta-openbmc-machines/meta-openpower/meta-ibm/meta-witherspoon/recipes-phosphor/ipmi/phosphor-ipmi-host.bbappend)

The JSON format for get_device_id:

    {"id": 0, "revision": 0, "addn_dev_support": 0,
        "manuf_id": 0, "prod_id": 0, "aux": 0}

Each value in this JSON object should be an integer. The file is placed in
/usr/share/ipmi-providers/ by Yocto, and will be parsed upon the first call to
get_device_id. The data is then cached for future use. If you change the data at
runtime, simply restart the service to see the new data fetched by a call to
get_device_id.

## IPMI D-Bus Sensor Filtering

Phosphor-ipmi-host provides a compile time option to control how IPMI sensors
are populated. The default model is for the sensors to be culled from a set of
JSON files. There is another model that collects the sensors to display from
D-Bus. The D-Bus method is the default mode used by Redfish. Redfish does not
have a fixed limit on the number of sensors that can be reported.

IPMI supports a smaller number of sensors than are available via Redfish. The
limit being the number of Sensor Data Records (SDR) supported in the IPMI
specification. Enabling IPMI to use D-Bus may cause the number of sensors
retrieved to exceed the number SDRs IPMI can support. Even if the number of
sensors retrieved is within the SDR limit IPMI can support, it may be desirable
to filter entries that are uninteresting.

Meson uses the _dyanmic-sensors_ configuration option to enable retrieving the
sensors via D-Bus. When dynamic sensors are active all of the sensors placed on
D-Bus by a service are added to the IPMI sensor list. In the event that too many
sensors are exposed on D-Bus, the list can be filtered by adding a list of
services to filter to _/usr/share/ipmi-providers/sensor_filter.json_.

Example filtering:

```json
{
  "ServiceFilter": [
    "xyz.openbmc_project.RedfishSensors1",
    "xyz.openbmc_project.RedfishSensors2"
  ]
}
```

Any sensors published by the example services are blocked from being added to
the IPMI SDR table.
