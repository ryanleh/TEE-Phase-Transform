from ai_utils.scenarios.abstract_scenario import AbstractScenarioClass
from ai_utils.scenarios.scenario_executor import ScenarioExecutorClass
{{ cookiecutter.phase_import_statements }}
import importlib
import logging
import sys

class {{ cookiecutter.scenario_class_name }}(AbstractScenarioClass):
    TrackerId = "{{ cookiecutter.scenario_guid }}"
    Subject = "{{ cookiecutter.scenario_name }}"
    Description = """{{ cookiecutter.scenario_description }}"""

    def __init__(self, model):
        AbstractScenarioClass.__init__(self)
        self._state = model
        self.phases = """{{ cookiecutter.phases }}""".split()

    def Run(self):
        state = {}
        state.update(self._state)

        for acp in self.phases:
            module_string = 'circadence_phases' + '.' + acp
            module = importlib.import_module(module_string)

            self.ScenarioReporter.Info('Creating {}.'.format(acp))
            phase = module.create(state)

            self.ScenarioReporter.Info('Starting {}'.format(acp))
            old_state = {k: v for k, v in state.items()}

            phase.Execute()

            state = phase.get_result()

            added = {k: v for k, v in state.items()
                     if k not in old_state}
            if added:
                self.ScenarioReporter.Info('Added: ' + str(added))

            changed = {k: v for k, v in state.items()
                       if k in old_state  # already in state
                       and not old_state[k] == state[k]}
            if changed:
                self.ScenarioReporter.Info('Changed: ' + str(changed))

            removed = {k: v for k, v in old_state.items()
                       if k not in state}
            if removed:
                self.ScenarioReporter.Info('Removed: ' + str(removed))


def run(*args):
    ScenarioExecutorClass().Run()


if __name__ == "__main__":
    run()
