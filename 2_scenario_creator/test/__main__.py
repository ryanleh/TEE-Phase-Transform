#/usr/bin/python2.7
"""
    Runs the scenario in this directory (treated as an executable module). Takes exploitrix-like CLI dict input and writes C{model.json} before
    running the scenario's C{main.py}.
"""

import argparse
import json
import sys
import re
import os


def get_options():
    """
        @return a dict of commandline parameter input.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--dictionary', default='',
                        help="Additional key-value options as a " +
                             "semicolon-delimited list of key = value pairs.")
    parser.add_argument('-j', '--json', default='',
                        help="Optional json formatted input from file")
    args = parser.parse_args()

    # Can't accept both.
    if args.dictionary and args.json:
        raise ValueError("You can't supply both dictionary and JSON args.")

    if args.dictionary:
        return parse_dict(args.dictionary)

    if args.json:
        return parse_json(args.json)

    # No params is fine too.
    return dict()


def parse_dict(kvlist):
    """
        Parse dictionary-like command line arguments

        @param kvlist: a string in the form 'key_1=value_1; ... ; key_n=value_n'

        @return: a dictionary with the above key, value pairs
    """

    options = dict()

    if kvlist:
        str_token_regex = r"""^\s*([^\s=]+)\s*=\s*([^\s=]+)\s*$"""

        for kv in kvlist.split(';'):
            kvmatcher = re.match(str_token_regex, kv)
            if kvmatcher is None:
                raise Exception('Illegal k-v argument: ' + kv)
            options[kvmatcher.group(1)] = kvmatcher.group(2)

    return options


def parse_json(json_file):
    """
    Parse a json file and put into dictionary

        @param json_file: json file/pathname as string
        @type json_file: string

        @return: dictionary equivalent of json file
    """
    if json_file:
        with open(json_file, 'r') as f:
            return json.load(f)


if __name__ == '__main__':
    params = get_options()

    # Report params
    print('You input these:')
    print('\n'.join(map(' = '.join, params.items())))

    # Get into the directory where the scenario's runtime resources are stored.
    os.chdir(os.path.split(__file__)[0])

    # Update to model.json.
    with open('model.json', 'r') as j:
        model = json.load(j)
    model.update(params)
    with open('model.json', 'w') as j:
        json.dump(model, j)

    # I love Python.
    sys.argv = ['main.py', 'model.json']
    __import__('main').run()
