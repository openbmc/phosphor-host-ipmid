#!/usr/bin/env python

import os
import sys
import yaml
import argparse
from mako import exceptions
from mako.template import Template


def generate_cpp(sensor_yaml, output_dir):
    with open(os.path.join(script_dir, sensor_yaml), 'r') as f:
        ifile = yaml.safe_load(f)
        if not isinstance(ifile, dict):
            ifile = {}

        # Render the mako template

        t = Template(filename=os.path.join(
                     script_dir,
                     "writesensor.mako.cpp"))

        output_cpp = os.path.join(output_dir, "sensor-gen.cpp")
        with open(output_cpp, 'w') as fd:
            try:
                fd.write(t.render(sensorDict=ifile))
            except:
                fd.write(exceptions.text_error_template().render())


def main():

    valid_commands = {
        'generate-cpp': generate_cpp
    }
    parser = argparse.ArgumentParser(
        description="IPMI Sensor parser and code generator")

    parser.add_argument(
        '-i', '--sensor_yaml', dest='sensor_yaml',
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

    if (not (os.path.isfile(os.path.join(script_dir, args.sensor_yaml)))):
        sys.exit("Can not find input yaml file " + args.sensor_yaml)

    function = valid_commands[args.command]
    function(args.sensor_yaml, args.outputdir)


if __name__ == '__main__':
    script_dir = os.path.dirname(os.path.realpath(__file__))
    main()
