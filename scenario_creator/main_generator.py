

"""
Build main.py based on phase objects

Make naming consistent?
"""
class Main(object):
    def __init__(self, subject, type, description):

        # TODO: make a generating tid
        self.tid = '123'
        self.subject = subject
        self.type = type
        self.description = description

    def _makeRun(self):
        """
        Write code to run phases in Run() function
        """

        """for phase in self.phases:
            "{} = {}(self, {}) ".format{phase.name, phase.classname, phase.params}
            "{}.Execute()"
        --> add something like this to Run() function"""
    def _makeSetup(self):
        """
        Write code to check if required params exist within model.json
        """

    def makeMain(self, phases):
        """
        Make Main based off phases object
        """
