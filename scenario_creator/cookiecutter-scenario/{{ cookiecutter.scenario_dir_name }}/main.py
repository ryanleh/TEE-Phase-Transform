from ai_utils.scenarios.abstract_scenario import AbstractScenarioClass
from ai_utils.scenarios.scenario_executor import ScenarioExecutorClass
{{ cookiecutter.phase_import_statements }}


class {{ cookiecutter.scenario_class_name }}(AbstractScenarioClass):
    TrackerId = "{{ cookiecutter.scenario_tid }}"
    Subject = "{{ cookiecutter.scenario_name }}"
    Description = "{{ cookiecutter.scenario_description }}"

    def __init__(self, model):
        AbstractScenarioClass.__init__(self)
        Setup(model)

    def Run(self):
        {{ cookiecutter.scenario_run }}

    def Setup(self, model):
        {{ cookiecutter.scenario_setup}}

def run(*args):
    ScenarioExecutorClass().Run()


if __name__ == "__main__":
    run()
