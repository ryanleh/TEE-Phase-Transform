import sys
import os
import importlib
import inspect
import shutil
import fileinput
import argparse
import re

root_directory = os.path.dirname(os.path.realpath(__file__))
phase_directory = os.path.join(root_directory, "bin/ai_utils/phases")
script_directory = os.path.join(root_directory, "scripts/")

def make_parser():
    """
        Create ArgumentParser object
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--phase', required=True,
                        help='A list containing all the desired phase names')
    return parser

def get_inputs(phase_path):
    """
        Populate list of required and optional arguments
    """

    req_inputs = {}
    opt_inputs = {}

    # TODO: more elegant solution
    file = open(phase_path)
    for line in file:
        line = line.lstrip()
        if line[:13] == "def __init__(":
            arg_list = re.search('def __init__\((.+?)\):', line).group(1).split(",")[2:]
            for arg in arg_list:
                if "=" not in arg:
                    req_inputs[arg.strip()] = ""
                else:
                    opt = arg.strip().split("=")
                    opt_inputs[opt[0]] = opt[1]
    file.close()


    return req_inputs, opt_inputs

def copy_phase(phase_path, cir_phase_path, init):
    """
        Convert phase to circadence phase
    """

    original = open(phase_path, 'r')
    copy = open(cir_phase_path, 'w')

    # TODO: come up with better solution
    # regex subs on each line and write line to file
    for line in original:
        line = re.sub(r"(from )ai_utils.phases.abstract_phase( import )AbstractPhaseClass", r"\1abstract_circadence_phase\2AbstractCircadencePhase", line)
        line = re.sub(r"(\s*class.*)AbstractPhaseClass", r"\1AbstractCircadencePhase", line)
        line = re.sub(r"(\s*def __init__\(self,).*", r"\1info):", line)
        line = re.sub(r"(\s*Abstract)(Phase)Class(.__init__\(self,).*", r"\1Circadence\2\3info=info)\n{}".format(init), line)
        copy.write(line)


def insert_req(phase, cir_phase_path, req_inputs, opt_inputs):
    """
        Put Create function and necessary input paramaters into phase
    """

    for line in fileinput.input(cir_phase_path, inplace=True):
        if re.match(r"^\s*Description.*\n", line):
            print(re.sub(r"(^\s*Description.*\n)",
                       r"\1\n    required_input_parameters = {}"\
                        "\n    optional_input_parameters = {}"\
                        "\n    output_parameters = {}".format(req_inputs,opt_inputs,"{}"), line))
        else:
            sys.stdout.write(line)

    #Get Classname
    phase_mod = importlib.import_module(phase[:-3])
    phase_mod_classes = inspect.getmembers(phase_mod, inspect.isclass)

    phase_mod_classes = filter(lambda (name, obj):
                               'ai_utils' not in str(obj) and name != "AbstractCircadencePhase",
                               phase_mod_classes)

    if len(phase_mod_classes) != 1:
        raise AttributeError

    phase_class = phase_mod_classes[0][0]

    #Append Create
    with open(cir_phase_path,"a") as file:
        file.write('\ndef create(info):\n    """\n        '\
            'Create a new instance of the phase\n    """\n'\
            '\n    return {}(info)\n'.format(phase_class))



def generate_init(req_inputs, opt_inputs):
    init = ""

    for req in req_inputs.keys():
        init += "\t{0} = self.PhaseResult['{0}']\n".format(req)
    for opt in opt_inputs:
        init += "\t{0} = self.PhaseResult['{0}']\n".format(opt)

    return init


def main():

    args = make_parser().parse_args()
    phase_path = os.path.join(phase_directory, args.phase)
    cir_phase_path = os.path.join(script_directory, args.phase)

    req_inputs, opt_inputs = get_inputs(phase_path)
    init = generate_init(req_inputs,opt_inputs)
    copy_phase(phase_path, cir_phase_path, init)


    insert_req(args.phase, cir_phase_path, req_inputs, opt_inputs)



    







if __name__ == '__main__':

    # Append phase and ai_utils directory to python path
    sys.path.append(os.path.join(root_directory,'scripts/'))
    # sys.path.append(os.path.join(root_directory,'./bin/ai_utils/phases'))

    main()