#!/usr/bin/env python

import os
import sys
import yaml
import argparse
from mako.template import Template


def generate_cpp(entity_yaml, output_dir):
    with open(entity_yaml, 'r') as f:
        ifile = yaml.safe_load(f)
        if not isinstance(ifile, dict):
            ifile = {}

        # Render the mako template

        t = Template(filename=os.path.join(
                     script_dir,
                     "writeentity.mako.cpp"))

        output_cpp = os.path.join(output_dir, "entity-gen.cpp")
        with open(output_cpp, 'w') as fd:
            fd.write(t.render(entityDict=ifile))


def main():

    valid_commands = {
        'generate-cpp': generate_cpp
    }
    parser = argparse.ArgumentParser(
        description="IPMI Entity record parser and code generator")

    parser.add_argument(
        '-i', '--entity_yaml', dest='entity_yaml',
        default='example.yaml', help='input entity yaml file to parse')

    parser.add_argument(
        "-o", "--output-dir", dest="outputdir",
        default=".",
        help="output directory")

    parser.add_argument(
        'command', metavar='COMMAND', type=str,
        choices=valid_commands.keys(),
        help='Command to run.')

    args = parser.parse_args()

    if (not (os.path.isfile(args.entity_yaml))):
        sys.exit("Can not find input yaml file " + args.entity_yaml)

    function = valid_commands[args.command]
    function(args.entity_yaml, args.outputdir)


if __name__ == '__main__':
    script_dir = os.path.dirname(os.path.realpath(__file__))
    main()
