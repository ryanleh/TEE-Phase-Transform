from ai_utils.scenarios.abstract_scenario import AbstractScenarioClass
from ai_utils.scenarios.scenario_executor import ScenarioExecutorClass



class Test(AbstractScenarioClass):
    TrackerId = "123"
    Subject = "Test"
    Description = "a Test"

    def __init__(self, model):
        AbstractScenarioClass.__init__(self)
        Setup(model)

    def Run(self):
        

    def Setup(self, model):
        

def run(*args):
    ScenarioExecutorClass().Run()


if __name__ == "__main__":
    run()
