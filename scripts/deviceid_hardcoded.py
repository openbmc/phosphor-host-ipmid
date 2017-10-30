#!/usr/bin/env python

import os
import sys
import yaml
import argparse
from mako.template import Template

tmpl = '''/* This is a generated file. */
#include "apphandler.h"

extern const InvDevIdInfo devidinfo = {
% for key in devDict.iterkeys():
   % if key:
<%
    property = devDict[key]
    SystemId = hex(property["System_Id"])
    SysRevId = hex(property["SysRevision_Id"])
    IpmiVersion = property["IpmiVersion"]
    AddnDevSupport = hex(property["Addn_Dev_Support"])
    ManufId = hex(property["Manufacturer_Id"])
    ProductId = hex(property["Product_Id"])
%>
    ${SystemId}, ${SysRevId}, ${IpmiVersion}, ${AddnDevSupport},

    ${ManufId}, ${ProductId}

   % endif
% endfor

};
'''

if __name__ == '__main__':

    script_dir = os.path.dirname(os.path.realpath(__file__))
    parser = argparse.ArgumentParser(
        description="IPMI System Specific Device Id info")

    parser.add_argument(
        "-i", "--deviceid_hardcoded_yaml", dest="deviceid_hardcoded_yaml",
        default="sample-deviceid-hardcoded.yaml", help="input device data file to parse")

    parser.add_argument(
        "-o", "--output_file", dest="output",
        default="deviceid_hardcoded.cpp",
        help="Generated output file")

    args = parser.parse_args()

    if (not (os.path.isfile(os.path.join(script_dir, args.deviceid_hardcoded_yaml)))):
        sys.exit("Can not find input yaml file " + args.deviceid_hardcoded_yaml)

    with open(os.path.join(script_dir,args.deviceid_hardcoded_yaml), 'r') as f:
        yfile = yaml.safe_load(f) or {}

    with open(args.output, 'w') as out:
        out.write(Template(tmpl).render(devDict=yfile))
