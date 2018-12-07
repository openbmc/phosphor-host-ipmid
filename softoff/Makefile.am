xyz/openbmc_project/Ipmi/Internal/SoftPowerOff/server.cpp: ${top_srcdir}/xyz/openbmc_project/Ipmi/Internal/SoftPowerOff.interface.yaml
	@mkdir -p `dirname $@`
	$(SDBUSPLUSPLUS) -r $(top_srcdir) interface server-cpp xyz.openbmc_project.Ipmi.Internal.SoftPowerOff > $@

xyz/openbmc_project/Ipmi/Internal/SoftPowerOff/server.hpp: ${top_srcdir}/xyz/openbmc_project/Ipmi/Internal/SoftPowerOff.interface.yaml
	@mkdir -p `dirname $@`
	$(SDBUSPLUSPLUS) -r $(top_srcdir) interface server-header xyz.openbmc_project.Ipmi.Internal.SoftPowerOff > $@

