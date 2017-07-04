from ai_utils.scenarios.abstract_scenario import AbstractScenarioClass
from ai_utils.scenarios.scenario_executor import ScenarioExecutorClass
{{ cookiecutter.phase_import_statements }}


class {{ cookiecutter.scenario_class_name }}(AbstractScenarioClass):
  TrackerId = "{{ cookiecutter.scenario_guid }}"
  Subject = "{{ cookiecutter.scenario_name }}"
  Description = "{{ cookiecutter.scenario_description }}"

  def __init__(self, model):
    AbstractScenarioClass.__init__(self)
    self.FirstParameter = self.SetupFirstParameter(model.get('first_parameter'))

  def Run(self):
{{ cookiecutter.phase_initialize_execute_statements }}

  def SetupFirstParameter(self, firstParameter):
    self.ScenarioReporter.Info('First Parameter value: {}'.format(firstParameter))
    return firstParameter


def run(*args):
  ScenarioExecutorClass().Run()


if __name__ == "__main__":
  run()
