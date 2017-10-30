#!/usr/bin/env python

import os
import sys
import yaml
import argparse
from mako.template import Template

tmpl = '''/* This is a generated file. */
#include "types.hpp"
using namespace ipmi::fru;

extern const InvDevIdInfo devidinfo = {
% for key in devDict.iterkeys():
   % if key:
<%
    property = devDict[key]
    Manufacturer_Id = hex(property["Manufacturer_Id"])
    Product_Id = hex(property["Product_Id"])
%>
    ${Manufacturer_Id}, ${Product_Id}

   % endif
% endfor

};
'''

if __name__ == '__main__':

    script_dir = os.path.dirname(os.path.realpath(__file__))
    parser = argparse.ArgumentParser(
        description="IPMI Device Id Manf Id and Prod Id info")

    parser.add_argument(
        "-i", "--deviceid_yaml", dest="deviceid_yaml",
        default="deviceid.yaml", help="input device data file to parse")

    parser.add_argument(
        "-o", "--output_dir", dest="output_dir",
        default=".",
        help="output directory")

    args = parser.parse_args()

    if (not (os.path.isfile(os.path.join(script_dir, args.deviceid_yaml)))):
        sys.exit("Can not find input yaml file " + args.deviceid_yaml)

    with open(os.path.join(script_dir,args.deviceid_yaml), 'r') as f:
        yfile = yaml.safe_load(f) or {}

    output_file = os.path.join(args.output_dir, "deviceid.cpp")
    with open(output_file, 'w') as output:
        output.write(Template(tmpl).render(devDict=yfile))
