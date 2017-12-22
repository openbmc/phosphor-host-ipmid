#!/usr/bin/env python

import os
import sys
import yaml
import argparse
from mako.template import Template


def generate_cpp(interface_yaml, output_dir):
    with open(os.path.join(script_dir, interface_yaml), 'r') as f:
        ifile = yaml.safe_load(f)
        if not isinstance(ifile, dict):
            ifile = {}

        # Render the mako template

        t = Template(filename=os.path.join(
                     script_dir,
                     "writechannel.mako.cpp"))

        output_cpp = os.path.join(output_dir, "channel-gen.cpp")
        with open(output_cpp, 'w') as fd:
            fd.write(t.render(interfaceDict=ifile))


def main():

    valid_commands = {
        'generate-cpp': generate_cpp
    }
    parser = argparse.ArgumentParser(
        description="IPMI ethernet interface parser and code generator")

    parser.add_argument(
        '-i', '--interface_yaml', dest='interface_yaml',
        default='example.yaml', help='input sensor yaml file to parse')

    parser.add_argument(
        "-o", "--output-dir", dest="outputdir",
        default=".",
        help="output directory")

    parser.add_argument(
        'command', metavar='COMMAND', type=str,
        choices=valid_commands.keys(),
        help='Command to run.')

    args = parser.parse_args()

    if (not (os.path.isfile(os.path.join(script_dir, args.interface_yaml)))):
        sys.exit("Can not find input yaml file " + args.interface_yaml)

    function = valid_commands[args.command]
    function(args.interface_yaml, args.outputdir)


if __name__ == '__main__':
    script_dir = os.path.dirname(os.path.realpath(__file__))
    main()
