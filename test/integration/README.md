# D-Bus Mocking for Integration Testing - IPMID Example

This directory includes examples of using the sdbusplus test infrastructure to
support mocking D-Bus services for integration testing as discussed in
[gerrit/37378](https://gerrit.openbmc-project.xyz/c/openbmc/docs/+/37378).
In this example, mock temperature sensor, BMC state, user manager, restriction
mode, and networkd services are run on a D-Bus
that is shared with an instance of ipmid daemon.
The ipmid capabilities in some of the commands managed by app handler,
sensor handler, and transport handler components are evaluated.

## Files

- common (note: This directory is the temporary place for common utilities that
can be used to run integration tests on other OpenBMC daemons too.
The appropriate place for these functions is TBD.)
	- common/mapperd_manager (duplicate commit from the pid-control example)
		- Manages mapperd daemon.
	- common/integration_test (duplicate commit from the pid-control example)
		- This is a base class to share utilities that can be used by all
        integration tests.
        - It will start the mapperx daemon upon construction.
		- A connection to bus established to handle cases such as calling a
		 method on D-Bus and listening on signals.
		- The timed loop will start by calling `runFor()`.
		- Simple bus related expectations, such as expecting signals, can be
        added. The expectations can be evaluated by the number of times they met
        using functions such as `exactly`, `atLeast`, and `atMost`.
	- common/services
		- common/services/sensor_server (duplicate commit from the pid-control
		example)
			- This is an example of an active mock sensor. It will increase the
            temperature sensor value each second.
			- Users add objects through the `addSensor()` function.
			- The service should be initialized first and all objects should be
			added, and then 'start()' method should explicitly be called to
			start the service.
			- By calling the start, the service starts a worked thread.
			- The worker thread opens a connection to bus, requests a well-known
			name, adds objects to the bus, and starts a timed loop.
			- The object should be added to the service before starting the
			service.
            - The sensor object implements Sensor.Value D-Bus interface.
		- common/services/bmc_state
			- This service is used for changing the state of BMC.
            - The mock object implements the State.BMC D-Bus
            interface.
		- common/services/user_manager
			- This service is used for creating users and changing users
			attributes.
            - Two mock objects implement the User.Manager and User.Attributes
			D-Bus interfaces.
		- common/services/restriction_mode
			- This service is required for setting up ipmid.
            - Two mock objects implement the Control.Security.RestrictionMode
			D-Bus interface.
		- common/services/networkd
			- This service mocks some functionalies of networkd
			(phosphor-networkd).
			- mock objects
				- NetworkManagerObject implements the Network.VLAN.Create
				interface.
				- EthernetInterfaceObject implements Network.EthernetInterface,
				Network.IP.Create, Network.MACAddress, and
				Network.Neighbor.CreateStatic D-Bus interfaces.
				- VLANInterfaceObject implements Network.VLAN and
				Network.EthernetInterface D-Bus interfaces.
				- SystemConfigurationObject implements the
				Network.SystemConfiguration interface.
- ipmid_test
	- This is a class to share functionalities used by all tests on ipmid.
	- It allows the user to initilize services, add objects, and start services.
	- The ipmid daemon will start after a call to `startIpmid`.
	- For each type of handler, there is an internal class that is responsible
	for executing the ipmid commands, verifying, and printing the responses.
- itest_app
	- This file includes 6 example tests based on apphandler that are run using
	gtest.
	- These tests include GetDeviceId, ColdReset, GetSelfTestResults,
	SetUsername, EnableUser, and SetUserAccess.
	- Some tests such as GetDeviceId need some configuration files available at
	a specific path to ipmid to function properly.
	- SetUsername is an example that mocks the `createUser` method of User
	Manager.
- itest_sensor
	- This file includes 3 example tests based on sensorhandler that are run
	using gtest.
	- These tests include GetDeviceSdrInfo, GetDeviceSdr, and GetSensorReading.
	- GetSensorReading works based on sensor-example.yaml file. Currently, this
	test fails because of the mismatch in data types (double vs int).
- itest_transport
	- This file includes 5 example tests based on transporthandler that are run
	using gtest.
	- These tests include IP Address, MAC Address, Gateway Address, Gateway MAC
	Address, and VLAN Create.
	- IP Address test mocks `iP` method of the IP.Create interface, MAC Address
	test mocks `mACAddress` method of the MACAddress interface, Gateway Address
	test mocks the setter method of `defaultGateway` method of the
	SystemConfiguration interface, Gateway MAC Address test mocks `neighbor`
	method of the Neighbor.CreateStatic interface, and VLAN Create test mocks
	`vLan` method of VLAN.Create interface.

## Requirements
This is an integration test for the ipmid daemon.
To function properly, ipmid expects some configuration files at specific
locations.
Examples of some of these configuration files are included in the `conf`
directory.
For example, providers should be available at `/usr/lib/ipmid-providers`.
`channel_access_nv.json` and `ipmi_user.json` should be available at
`/var/lib/ipmi/`.
`channel_config.json` should be available at `/usr/share/ipmi-providers/`.
ipmid should have proper access to copy files to `/run/ipmi/`.

In addition, some tests require more configuration files. These issues are
mentiond above in this document above and by comment in the test code.
