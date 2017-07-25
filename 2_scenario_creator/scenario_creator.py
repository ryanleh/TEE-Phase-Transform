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


# TODO: handle inputs that aren't in stdlib


def make_parser():
    """
        @return: an C{ArgumentParser} object that can parse this script's
        commandline arguments.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-p','--phase_list', required=True, nargs = '+',
                        help='A list containing all the desired phase names')
    parser.add_argument('-n','--scenario_name', required=True, help='Name of scenario')
    parser.add_argument('-t', '--type', default=1,help='Specify whether scenario is'\
                            ' an attack or a validation')
    parser.add_argument('-d', '--description', default='Description', help='Scenario description')


    return parser


def read_ac(acpath):
    """
        @param acpath: path to an AC listing
        @return: a list of modules in this AC
    """
    with open(acpath, 'r') as aclines:
        return [phase_name.strip() for phase_name in aclines]


def read_description(phase_list):
    """
        @param phase_list: a path corresponding to an AC listing
        @return: the documentation's given description
    """
    with open(os.path.join('../doc/scripts',
                           os.path.split(phase_list)[1]),
              'r') as d:
        return d.read()


def parameters(args):
    """
        @param args: argument magic object parsed by C{argparse} 
        @return: a field-description dict of parameters that you need to run 
            the phase from start to end.
    """

    req_params = {}
    opt_params = {}

    for phase in reversed(args.phase_list):

        phase_mod = importlib.import_module(phase)
        phase_mod_classes = inspect.getmembers(phase_mod, inspect.isclass)

        # TODO: this line is sketchy
        phase_mod_classes = filter(lambda (name, obj):
                                   'ai_utils' not in str(obj) and name != "AbstractCircadencePhase",
                                   phase_mod_classes)
        if len(phase_mod_classes) != 1:
            raise AttributeError

        phase_class = phase_mod_classes[0][1]

        # Idea:
        # required_inputs -= current_outputs
        # required_inputs += current_inputs
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


def descriptor(args):
    required_input,optional_input = parameters(args)

    desc = {}
    desc['resources'] = []

    resources = {   "engine": "ai_python.exe",
                    "entryscript": "main.py",
                    # 1 for attack, 2 for verification
                    "scenario_type": 2,
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
    cookie_dict['scenario_dir_name'] = args.scenario_name
    cookie_dict['scenario_name'] = args.scenario_name
    cookie_dict['scenario_class_name'] = args.scenario_name + "ScenarioClass"
    cookie_dict['scenario_description'] = args.description
    cookie_dict['scenario_guid'] = str(uuid.uuid4())
    cookie_dict['supported_platforms'] = ''
    cookie_dict['phases'] = '\n'.join(args.phase_list)

    import_statements = ''
    for phase in cookie_dict['phases'].split():
        import_statements = import_statements + 'import circadence_phases.{0}\n'.format(phase)

    cookie_dict['phase_import_statements'] = import_statements

    return cookie_dict


def main():
    root_directory = os.path.dirname(os.path.realpath(__file__))
    args = make_parser().parse_args()

    print(args)


    req_dict, opt_dict = parameters(args)
    input_dict = req_dict.copy()
    input_dict.update(opt_dict)
    cookiecutter_dict = cookie(args)
    descriptor_dict = descriptor(args)

    with open("circscenario-template/{{ cookiecutter.scenario_dir_name }}/descriptor.json", 'w') as j:
        json.dump(descriptor_dict, j, indent=4)

    print('\n'.join(map(str, descriptor_dict.items())))


    with open("circscenario-template/{{ cookiecutter.scenario_dir_name }}/model.json", 'w') as j:
        json.dump(input_dict, j)

    print('\n'.join(map(str, input_dict.items())))

    cookiecutter(os.path.join(root_directory,"./circscenario-template"), no_input=True, extra_context=cookiecutter_dict)

    scenario_dir = os.path.join(root_directory, args.scenario_name)

    circadence_phases_dir = os.path.join(scenario_dir, 'circadence_phases')
    os.mkdir(circadence_phases_dir)

    open(os.path.join(scenario_dir,"circadence_phases/__init__.py"),'w')

    # copy AbstractCircadencePhase to target dir
    shutil.copy('abstract_circadence_phase.py', scenario_dir)

    for mod in cookiecutter_dict['phases'].split():
        shutil.copy(os.path.join('./scripts', mod + '.py'),circadence_phases_dir)

    try:
        shutil.copytree(os.path.join(root_directory,"bin"), os.path.join(scenario_dir, 'bin'))
    except OSError as exc:
        if exc.errno == errno.ENOTDIR:
            shutil.copy(os.path.join(root_directory,"bin"), os.path.join(scenario_dir, 'bin'))


if __name__ == '__main__':

    # Append phase and ai_utils directory to python path
    root_directory = os.path.dirname(os.path.realpath(__file__))
    phase_directory = os.path.join(root_directory,'scripts/')
    sys.path.append(phase_directory)
    sys.path.append('./bin')

    main()
