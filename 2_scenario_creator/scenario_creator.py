from cookiecutter.main import cookiecutter
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
import errno
import traceback
import glob

root_directory = os.path.dirname(os.path.realpath(__file__))

# Add to this once more phases have been converted
external_imports = ['nmap']

def make_parser():
    """
        Builds ArgumentParser Object
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-p','--phase_list', required=True, nargs = '+',
                        help='A list containing all the desired phase names')
    parser.add_argument('-n','--scenario_name', required=True, help='Name of scenario')
    parser.add_argument('-t', '--type', default=1,help='Specify whether scenario is'\
                            ' an attack or a validation')
    parser.add_argument('-d', '--description', default='Description', help='Scenario description')


    return parser

def get_parameters(args):
    """
        Return dictionaries of required and optional parameters

    """

    req_params = {}
    opt_params = {}

    for phase in reversed(args.phase_list):

        phase_mod = importlib.import_module(phase)
        phase_mod_classes = inspect.getmembers(phase_mod, inspect.isclass)

        phase_class = [cls for cls in phase_mod_classes if cls[1].__module__ == phase][0][1]

        if len(phase_mod_classes) == 0:
            print("Error in finding class object")
            raise AttributeError

        # Keep all inputs which aren't outputs of previous phases
        req_params = {field: desc
                                    for field, desc
                                    in req_params.items()
                                    if field not in phase_class.get_outputs()}
        req_params.update(phase_class.get_req_inputs())

        opt_params = {field: desc
                                    for field, desc
                                    in opt_params.items()
                                    if field not in phase_class.get_outputs()}
        opt_params.update(phase_class.get_opt_inputs())

    return req_params, opt_params


def build_descriptor(args):
    """
        Builds descriptor.json
    """
    required_input,optional_input = get_parameters(args)

    all_input = required_input.copy()
    all_input.update(optional_input)

    desc = {}
    desc['resources'] = []

    resources = {   "engine": "ai_python.exe",
                    "entryscript": "main.py",
                    "scenario_type": 1,
                    "scenario_description": "{{ cookiecutter.scenario_description }}",
                    "tracker_id": "{{ cookiecutter.scenario_guid }}",
                    "subject": "{{ cookiecutter.scenario_name }}",
                    "supported_platforms": "{{ cookiecutter.supported_platforms }}",
                    "schema": {},
                    "form": []
                    }

    schema = {  "type": "object",
                "required": [],
                "properties": {}
                }

    schema['required'] = required_input.keys()

    for param, value in all_input.items():
        schema['properties'][param] = { "title": param,
                                        "type": "string",
                                        "default": value
                                        }
        resources['form'].append( {"key": param, "type": "text"} )

    resources['schema'] = schema
    desc['resources'].append(resources)
    return desc


def build_cookiecutter(args):
    """
        Builds cookiecutter.json
    """
    cookie_dict = { "scenario_dir_name": args.scenario_name,
                    "scenario_name": args.scenario_name,
                    "scenario_class_name": args.scenario_name + "ScenarioClass",
                    "scenario_description": args.description,
                    "scenario_guid": str(uuid.uuid4),
                    "supported_platforms": '',
                    "phases": '\n'.join(args.phase_list)
                    }

    import_statements = ''
    for phase in cookie_dict['phases'].split():
        import_statements += 'import circadence_phases.{0}\n'.format(phase)

    cookie_dict['phase_import_statements'] = import_statements

    return cookie_dict


def filter_imports(args):
    """
        Check if any external imports are needed
    """

    phase_list = args.phase_list

    imports = []

    for phase in phase_list:
        mod = importlib.import_module(phase)
        mod_imports = inspect.getmembers(mod, inspect.ismodule)
        for imp in mod_imports:
            for external_import in external_imports:
                if imp[0] == external_import:
                    imports.append(imp[0])

    return imports


def main():
    args = make_parser().parse_args()

    # Set path variables
    scenario_dir = os.path.join(root_directory, args.scenario_name)

    # Grab all inputs and build cookiecutter, descriptor, and model objects
    req_dict, opt_dict = get_parameters(args)
    input_dict = req_dict.copy()
    input_dict.update(opt_dict)
    cookiecutter_dict = build_cookiecutter(args)
    descriptor_dict = build_descriptor(args)

    with open("circscenario-template/{{ cookiecutter.scenario_dir_name }}/descriptor.json", 'w') as j:
        json.dump(descriptor_dict, j, indent=4)

    with open("circscenario-template/{{ cookiecutter.scenario_dir_name }}/model.json", 'w') as j:
        json.dump(input_dict, j)

    cookiecutter(os.path.join(root_directory,"./circscenario-template"), no_input=True, extra_context=cookiecutter_dict)

    # Cookiecutter acts weird with folders sometimes so we're moving folders afterwards
    # Create circadence_phases directory and move appropiate phases into it
    circadence_phases_dir = os.path.join(scenario_dir, 'circadence_phases')
    os.mkdir(circadence_phases_dir)
    open(os.path.join(scenario_dir,"circadence_phases/__init__.py"),'w')
    for mod in cookiecutter_dict['phases'].split():
        shutil.copy(os.path.join('./scripts', mod + '.py'),circadence_phases_dir)

    # copy AbstractCircadencePhase to scenario dir
    shutil.copy('abstract_circadence_phase.py', scenario_dir)

    # Copy ai_utils + other needed dependecies into bin directory
    try:
        shutil.copytree(os.path.join(root_directory,"bin"), os.path.join(scenario_dir, 'bin'))
    except OSError as exc:
        if exc.errno == errno.ENOTDIR:
            shutil.copy(os.path.join(root_directory,"bin"), os.path.join(scenario_dir, 'bin'))

    # Move any needed external imports
    ext_imports = filter_imports(args)

    for ext_import in ext_imports:
        module = os.path.join(root_directory, "bin/",ext_import)
        for data in glob.glob(module + "*"):
            shutil.copy(module, os.path.join(scenario_dir, "bin"))


if __name__ == '__main__':

    # Append phase and ai_utils directory to python path
    phase_directory = os.path.join(root_directory,'scripts/')
    sys.path.append(phase_directory)
    sys.path.append('./bin')

    main()
