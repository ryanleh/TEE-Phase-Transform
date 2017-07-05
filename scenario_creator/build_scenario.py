import os

from phase_params import PhaseParams
from main_generator import Scenario

phase_dir = "/home/ryan/projects/scenario_creator/cookiecutter-scenario/{{ cookiecutter.scenario_dir_name }}/bin/ai_utils/phases"


"""
Builds directory and generates all necessary files
"""
class ScenarioBuilder(object):
    def __init__(self):
        pass

    def _buildDir(self):
        """
        Builds Scenario file directory
        """

    def _getPhaseObject(self, phase_name):
        """
        Grab all requested Phase Objects
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
        Main program function --> NEED TO PUT IT CHECKS FOR INPUT
        """
        scenario_name = raw_input("What do you want to name the scenario? ")
        scenario_type = input("Is this scenario an attack(1) or a validation(2)?")
        scenario_description = raw_input("How do you want to describe the scenario? ")

        scenario = Scenario(scenario_name, scenario_type, scenario_description)

        phases = []
        num_of_phases = input("How many phases do you want? ")
        for i in range(1, num_of_phases + 1):
            phase_name = raw_input("What is the phase {}'s file name? ".format(i))
            phases.append(self._getPhaseObject(phase_name))





ScenarioBuilder().Run()