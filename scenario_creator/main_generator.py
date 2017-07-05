

"""
Build main.py based on phase objects
"""
class Scenario(object):
    def __init__(self):
        pass

    def _getInfo(self):
        """
        Get TID, subject, type, and description
        """

    def _makeRun(self):
        """
        Write code to run phases in Run() function

        for phase in self.phases:
            "{} = {}(self, {}) ".format{phase.name, phase.classname, phase.params}
            "{}.Execute()"
        --> add something like this to Run() function
        """

    def _makeSetup(self):
        """
        Write code to check if required params exist within model.json
        """

    def makeScenario(self, phases):
        """
        Make scenario based off phases object
        """
