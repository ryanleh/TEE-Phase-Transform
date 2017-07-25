from cookiecutter.main import cookiecutter
from append_directory_to_path import append_to_path
import importlib
import os
import sys
import shutil
import argparse
import re
import uuid
import json
import tempfile
import inspect


def make_parser():
    """
        @return: an C{ArgumentParser} object that can parse this script's
        commandline arguments.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-p','--phase_list', type=list, required=True,
                        help='A list containing all the desired phase names')
    parser.add_argument('-n','--scenario_name', required=True, help='Name of scenario')
    parser.add_argument('-t', '--type', default=1,help='Specify whether scenario is'\
                            ' an attack or a validation')
    parser.add_argument('-d', '--description', default='', help='Scenario description')


    return parser


def read_ac(acpath):
    """
        @param acpath: path to an AC listing
        @return: a list of modules in this AC
    """
    with open(acpath, 'r') as aclines:
        return [phase_name.strip() for phase_name in aclines]


def read_description(acfile):
    """
        @param acfile: a path corresponding to an AC listing
        @return: the documentation's given description
    """
    with open(os.path.join('../doc/scripts',
                           os.path.split(acfile)[1]),
              'r') as d:
        return d.read()


def required_parameters(args):
    """
        @param args: argument magic object parsed by C{argparse} 
        @return: a field-description dict of parameters that you need to run 
            the phase from start to end.
    """
    phases = read_ac(args.acfile)
    required_scenario_inputs = dict()

    for phase in reversed(phases):
        phase_mod = importlib.import_module(phase)
        phase_mod_classes = inspect.getmembers(phase_mod, inspect.isclass)
        phase_mod_classes = filter(lambda (name, obj):
                                   name != 'AbstractCircadencePhase',
                                   phase_mod_classes)
        if len(phase_mod_classes) != 1:
            raise AttributeError

        phase_class = phase_mod_classes[0][1]

        # Idea:
        # required_inputs -= current_outputs
        # required_inputs += current_inputs
        required_scenario_inputs = {field: desc
                                    for field, desc
                                    in required_scenario_inputs.items()
                                    if field not in phase_class.get_outputs()}
        required_scenario_inputs.update(phase_class.get_inputs())

    return required_scenario_inputs


def descriptor(args):
    required_input = required_parameters(args)

    desc = dict()
    desc['resources'] = list()

    resources = {   "engine": "ai_python.exe",
                    "entryscript": "main.py",
                    # 1 for attack, 2 for verification
                    "scenario_type": 1,
                    "scenario_description": "{{ cookiecutter.scenario_description }}",
                    "tracker_id": "{{ cookiecutter.scenario_guid }}",
                    "subject": "{{ cookiecutter.scenario_name }}",
                    "supported_platforms": "{{ cookiecutter.supported_platforms }}",
                    "schema": dict(),
                    "form": list()
                    }

    schema = {  "type": "object",
                "required": list(),
                "properties": dict()
                }

    schema['required'] = list(required_input.keys())

    for param, value in required_input.items():
        schema['properties'][param] = { "title": param,
                                        "type": "string",
                                        "default": value
                                        }
        resources['form'].append( {"key": param, "type": "text"} )

    resources['schema'] = schema
    desc['resources'].append(resources)
    return desc


def cookie(args):
    cookie_dict = dict()
    cookie_dict['scenario_dir_name'] = os.path.realpath(args.scenario_dir)
    cookie_dict['scenario_name'] = re.match(r'^(.+)\.txt$',
                                       os.path.split(args.acfile)[1]).group(1)
    cookie_dict['scenario_file_name'] = cookie_dict['scenario_name'] + '.py'
    cookie_dict['scenario_class_name'] = re.subn('[^\w\W\d_]', '',
                                            cookie_dict['scenario_name'])
    cookie_dict['scenario_description'] = read_description(args.acfile)
    cookie_dict['scenario_guid'] = str(uuid.uuid4())
    cookie_dict['supported_platforms'] = ''
    cookie_dict['exploitrix_phases'] = '\n'.join(read_ac(args.acfile))

    import_statements = ''
    for phase in cookie_dict['exploitrix_phases'].split():
        import_statements = import_statements + 'import circadence_phases.{0}\n'.format(phase)

    cookie_dict['phase_import_statements'] = import_statements

    return cookie_dict


def main():
    args = make_parser().parse_args()

    tempdir = tempfile.mkdtemp()
    templatedir = tempdir + '/TEMP'

    model_dict = required_parameters(args)
    cookiecutter_dict = cookie(args)
    descriptor_dict = descriptor(args)

    shutil.copytree('circscenario-template', templatedir)

    with open(os.path.join(templatedir,
                           'cookiecutter.json'), 'w') as j:
        json.dump(cookiecutter_dict, j)

    print('\n'.join(map(str, cookiecutter_dict.items())))

    with open(os.path.join(templatedir,
                            "{{ cookiecutter.scenario_dir_name }}",
                            'descriptor.json'), 'w') as j:
        json.dump(descriptor_dict, j, indent=4)

    print('\n'.join(map(str, descriptor_dict.items())))

    with open(os.path.join(templatedir,
                            "{{ cookiecutter.scenario_dir_name }}",
                            'model.json'), 'w') as j:
        json.dump(model_dict, j)

    print('\n'.join(map(str, model_dict.items())))

    # first delete the target dir
    shutil.rmtree(args.scenario_dir, ignore_errors=True)
    # execute the cookiecutter
    cookiecutter(templatedir, no_input=True, output_dir=args.scenario_dir,
                 overwrite_if_exists=True)
    # remove the template
    shutil.rmtree(tempdir)

    # copy the necessary scripts over
    circadence_phases_dir = os.path.join(args.scenario_dir, 'circadence_phases')
    os.mkdir(circadence_phases_dir)

    # copy AbstractCircadencePhase to target dir
    shutil.copy('abstract_circadence_phase.py', args.scenario_dir)

    # __init__.py so dir circadence_phases is a module
    with open(os.path.join(circadence_phases_dir, '__init__.py'), 'w') as init:
        init.write('\n')  # terminate empty file with a newline :)
    for mod in cookiecutter_dict['exploitrix_phases'].split():
        # print(os.path.join('./scripts', mod + '.py'))
        shutil.copy(os.path.join('./scripts', mod + '.py'),
                    circadence_phases_dir)

if __name__ == '__main__':

    # Append phase directory to python path
    root_directory = os.path.dirname(os.path.realpath(__file__))
    phase_directory = os.path.join(root_directory,'bin/ai_utils/phases')
    sys.path.append(phase_directory)
    main()
