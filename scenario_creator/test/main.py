from ai_utils.scenarios.abstract_scenario import AbstractScenarioClass
from ai_utils.scenarios.scenario_executor import ScenarioExecutorClass
from get_alive_hosts import GetAliveHostsPhaseClass


class test(AbstractScenarioClass):
    TrackerId = "123"
    Subject = "test"
    Description = "idk"

    def __init__(self, model):
        AbstractScenarioClass.__init__(self)
        self.ip_list = model.get('ip_list')
	self.n_threads = model.get('n_threads')
	self.timeout = model.get('timeout')
	self.use_arp = model.get('use_arp')
	

    def Run(self):
        get_alive_hosts = GetAliveHostsPhaseClass(True, self.ip_list, self.n_threads, self.timeout, self.use_arp)
	get_alive_hosts.Execute()
	

    def Setup(self):
        return True

def run(*args):
    ScenarioExecutorClass().Run()


if __name__ == "__main__":
    run()
