
from build_scenario import ScenarioBuilder
from main_generator import Main
from json_generator import JsonFiles
from cookiecutter.main import cookiecutter


# TODO: Make these dynamic - global parameter class? Or maybe just a function
builder_root = "/home/ryan/projects/scenario_creator"
phase_dir = "/home/ryan/projects/scenario_creator/bin/ai_utils/phases"
template_dir = "/home/ryan/projects/scenario_creator/cookiecutter-scenario/"
library_dir = "/home/ryan/projects/scenario_creator/bin"
def main():
    """
    Main program function

    TODO: Make checks for inputs
    """
    builder = ScenarioBuilder()
    
    scenario_name = raw_input("What do you want to name the scenario? ")
    scenario_type = input("Is this scenario an attack (1) or a validation (2)? ")
    scenario_description = raw_input("How do you want to describe the scenario? ")


    num_of_phases = input("How many phases do you want? ")
    for i in range(1, num_of_phases + 1):
        phase_name = raw_input("What is the phase {}'s file name? ".format(i))
        builder.phases.append(builder._getPhaseObject(phase_name))

    for phase in builder.phases:
        builder.req_params += phase.req_params
        builder.opt_params += phase.opt_params
        builder.imports = phase.imports


    builder.main = Main(scenario_name, scenario_type, scenario_description, builder.phases)
    builder.jsonGen = JsonFiles(builder.req_params, builder.opt_params)

    builder._buildContext()

    cookiecutter(template_dir, no_input=True, extra_context=builder.context)
    builder._moveDependencies()
    
