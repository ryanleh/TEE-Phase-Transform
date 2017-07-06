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
        self.phase_names = []

    def _buildContext(self):
        """
        Builds Cookiecutter context json object
        """

        self.context = {
            "scenario_dir_name": self.main.subject,


            "scenario_description": self.main.description,
            "scenario_tid": self.main.tid,
            "scenario_type": self.main.type,
            "supported_platforms": "{'ubuntu': '>=0.0', 'debian': '>=0.0', 'redhat': '>=0.0', 'linuxmint': '>=0.0', 'windows': '>=6.0', 'osx': '>=0.0'}",

            "required_params": self.req_params,
            "schema_properties": self.jsonGen.generateDescriptorSchema(),
            "form_parameters": self.jsonGen.generateDescriptorForm(),

            "scenario_run": "",
            "scenario_setup": "",

            "model_parameters": self.jsonGen.generateModel(),
            "phase_import_statements": ""
        }

        for phase_name in self.phase_names:
            self.context["phase_import_statements"] += "import {}\n".format(phase_name)


    def _getPhaseObject(self, phase_name):
        """
        Grab all requested Phase Objects

        >>> ScenarioBuilder._getPhaseObject(ScenarioBuilder(),"tcp_connect") #doctest: +ELLIPSIS
        <phase_params.PhaseParams object at 0x...>

        >>> ScenarioBuilder._getPhaseObject(ScenarioBuilder(),"tcp_con") #doctest: +ELLIPSIS
        IO Error: [Errno 2] No such file or directory:...
        """

        if phase_name[-3:] != ".py":
            phase_name += ".py"

        phase_path = os.path.join(phase_dir, phase_name)

        try:
            open(phase_path)
        except IOError as e:
            print("IO Error: {}".format(e))
            return

        return PhaseParams(phase_name, phase_path)


    def _generateMain(self):
        """
        Generate main.py
        """

    def _generateJson(self):
        """
        Generate Json files
        """

    def Run(self):
        """
        Main program function --> NEED TO PUT IN CHECKS FOR INPUT

        Also, move this out of the class definition perhaps?
        """
        scenario_name = raw_input("What do you want to name the scenario? ")
        scenario_type = input("Is this scenario an attack (1) or a validation (2)? ")
        scenario_description = raw_input("How do you want to describe the scenario? ")

        self.main = Main(scenario_name, scenario_type, scenario_description)

        phases = []
        num_of_phases = input("How many phases do you want? ")
        for i in range(1, num_of_phases + 1):
            phase_name = raw_input("What is the phase {}'s file name? ".format(i))
            phases.append(self._getPhaseObject(phase_name))

        for phase in phases:
            self.req_params += phase.req_params
            self.opt_params += phase.opt_params
            self.imports = phase.imports
            self.phase_names.append(phase.name[:-3])

        self.jsonGen = JsonFiles(self.req_params, self.opt_params)
        self._buildContext()

        cookiecutter(template_dir, no_input=True, extra_context=self.context)


        # TODO: figure out correct way to find these directories
        try:
            print(library_dir)
            print(os.path.join(builder_root, self.main.subject))
            shutil.copytree(library_dir, os.path.join(builder_root, self.main.subject + '/bin'))
        except OSError as exc:
            if exc.errno == errno.ENOTDIR:
                shutil.copy(library_dir, os.path.join(builder_root, self.main.subject + '/bin'))



ScenarioBuilder().Run()


