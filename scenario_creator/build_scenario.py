import os
import shutil
import errno

from phase_params import PhaseParams
from main_generator import Main
from json_generator import JsonFiles
from cookiecutter.main import cookiecutter


# TODO: Make these dynamic - global parameter class? Or maybe just a function
builder_root = "/home/ryan/projects/scenario_creator"
phase_dir = "/home/ryan/projects/scenario_creator/bin/ai_utils/phases"
template_dir = "/home/ryan/projects/scenario_creator/cookiecutter-scenario/"
library_dir = "/home/ryan/projects/scenario_creator/bin"

"""
Builds directory and generates all necessary files
"""
class ScenarioBuilder(object):
    def __init__(self):
        self.req_params = []
        self.opt_params = []
        self.imports = []
        self.phases = []
        self.params = ""

    def _buildContext(self):
        """
        Builds Cookiecutter context json object
        """

        self.context = {
            "scenario_dir_name": self.main.subject,


            "scenario_description": self.main.description,
            "scenario_tid": self.main.tid,
            "scenario_type": self.main.type,
            "supported_platforms": """{'ubuntu': '>=0.0', 'debian': '>=0.0',
                                       'redhat': '>=0.0', 'linuxmint': '>=0.0',
                                       'windows': '>=6.0', 'osx': '>=0.0'}""",

            "required_params": "",
            "schema_properties": self.jsonGen.generateDescriptorSchema(),
            "form_parameters": self.jsonGen.generateDescriptorForm(),

            "scenario_run": self.main._makeRun(),
            "scenario_setup": self.main._makeSetup(),
            "scenario_init": self.main._makeInit(),

            "model_parameters": self.jsonGen.generateModel(),
            "phase_import_statements": ""
        }

        for phase in self.phases:
            self.context["phase_import_statements"] += "from ai_utils.phases.{} import {}\n".format(phase.name, phase.class_name)

        # Have to format req_params for cookiecutter TODO: do this elegantally
        params = ""
        for param in self.req_params:
            self.context["required_params"] += '"{}", '.format(param)
        self.context["required_params"] = self.context["required_params"][:-2]


    def _getPhaseObject(self, phase_name):
        """
        Grab all requested Phase Objects

        >>> ScenarioBuilder._getPhaseObject(ScenarioBuilder(),"tcp_connect") #doctest: +ELLIPSIS
        <phase_params.PhaseParams object at 0x...>

        >>> ScenarioBuilder._getPhaseObject(ScenarioBuilder(),"tcp_con") #doctest: +ELLIPSIS
        IO Error: [Errno 2] No such file or directory:...
        """

        if phase_name[-3:] != ".py":
            phase_path = os.path.join(phase_dir, phase_name + '.py')
        else:
            phase_path = os.path.join(phase_dir, phase_name)

        try:
            open(phase_path)
        except IOError as e:
            print("IO Error: {}".format(e))
            return

        return PhaseParams(phase_name, phase_path)


    def _moveDependencies(self):
        """
        Move necessary libraries and phases into scenario directory
        """
        # TODO: figure out more 'correct' way to find these directories
        try:
            shutil.copytree(library_dir, os.path.join(builder_root, self.main.subject + '/bin'))

        except OSError as exc:
            if exc.errno == errno.ENOTDIR:
                shutil.copy(library_dir, os.path.join(builder_root, self.main.subject + '/bin'))


    def Run(self):
        """
        Main program function

        TODO: Make checks for inputs, move this out of the class definition
        """
        scenario_name = raw_input("What do you want to name the scenario? ")
        scenario_type = input("Is this scenario an attack (1) or a validation (2)? ")
        scenario_description = raw_input("How do you want to describe the scenario? ")


        num_of_phases = input("How many phases do you want? ")
        for i in range(1, num_of_phases + 1):
            phase_name = raw_input("What is the phase {}'s file name? ".format(i))
            self.phases.append(self._getPhaseObject(phase_name))

        for phase in self.phases:
            self.req_params += phase.req_params
            self.opt_params += phase.opt_params
            self.imports = phase.imports


        self.main = Main(scenario_name, scenario_type, scenario_description, self.phases)
        self.jsonGen = JsonFiles(self.req_params, self.opt_params)

        self._buildContext()

        cookiecutter(template_dir, no_input=True, extra_context=self.context)
        self._moveDependencies()





ScenarioBuilder().Run()
