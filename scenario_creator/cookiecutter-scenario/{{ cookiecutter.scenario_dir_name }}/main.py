from ai_utils.scenarios.abstract_scenario import AbstractScenarioClass
from ai_utils.scenarios.scenario_executor import ScenarioExecutorClass
{{ cookiecutter.phase_import_statements }}


class {{ cookiecutter.scenario_dir_name }}(AbstractScenarioClass):
    TrackerId = "{{ cookiecutter.scenario_tid }}"
    Subject = "{{ cookiecutter.scenario_dir_name }}"
    Description = "{{ cookiecutter.scenario_description }}"

    def __init__(self, model):
        AbstractScenarioClass.__init__(self)
        {{ cookiecutter.scenario_init }}

    def Run(self):
        {{ cookiecutter.scenario_run }}

    def Setup(self):
        {{ cookiecutter.scenario_setup}}

def run(*args):
    ScenarioExecutorClass().Run()


if __name__ == "__main__":
    run()
