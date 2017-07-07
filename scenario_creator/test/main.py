from ai_utils.scenarios.abstract_scenario import AbstractScenarioClass
from ai_utils.scenarios.scenario_executor import ScenarioExecutorClass
from ai_utils.phases.tcp_connect import Tcp_connectPhaseClass


class test(AbstractScenarioClass):
    TrackerId = "123"
    Subject = "test"
    Description = "test"

    def __init__(self, model):
        AbstractScenarioClass.__init__(self)
        self.ip = model.get('ip')
	self.port = model.get('port')
	self.message = model.get('message')
	

    def Run(self):
        tcp_connect = Tcp_connectPhaseClass(True, self.ip, self.port, self.message)
	tcp_connect.Execute()
	

    def Setup(self):
        return True

def run(*args):
    ScenarioExecutorClass().Run()


if __name__ == "__main__":
    run()
