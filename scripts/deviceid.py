#!/usr/bin/env python

import os
import sys
import yaml
import argparse
from mako.template import Template

tmpl = '''/* This is a generated file. */
#include "apphandler.h"
extern const IpmiDevIdInfo devIdInfo = {

<%
systemId = hex(devDict["System_Id"])
sysRevId = hex(devDict["SysRevision_Id"])
ipmiVersion = devDict["IpmiVersion"]
addnDevSupport = hex(devDict["Addn_Dev_Support"])
manufId = hex(devDict["Manufacturer_Id"])
productId = hex(devDict["Product_Id"])
%>
${systemId}, ${sysRevId}, ${ipmiVersion}, ${addnDevSupport}, ${manufId}, ${productId}

};
'''

if __name__ == '__main__':

    script_dir = os.path.dirname(os.path.realpath(__file__))
    parser = argparse.ArgumentParser(
        description="System Specific Get Device Id command info")

    parser.add_argument(
        "-i", "--deviceid_hardcoded_yaml", dest="deviceid_hardcoded_yaml",
        default="deviceid-example.yaml", help="input device data file to parse")

    parser.add_argument(
        "-o", "--output_file", dest="output",
        default="deviceid.cpp",
        help="Generated output file")

    args = parser.parse_args()

    if (not (os.path.isfile(os.path.join(script_dir, args.deviceid_hardcoded_yaml)))):
        sys.exit("Can not find input yaml file " + args.deviceid_hardcoded_yaml)

    with open(os.path.join(script_dir,args.deviceid_hardcoded_yaml), 'r') as f:
        yfile = yaml.safe_load(f) or {}

    with open(args.output, 'w') as out:
        out.write(Template(tmpl).render(devDict=yfile))
