
"""
Build main.py based on phase objects

No checks in place for whether an argument was in the model
"""
class Main(object):
    def __init__(self, subject, type, description, phases):

        # TODO: make a generating tid
        self.tid = '123'
        self.subject = subject
        self.type = type
        self.description = description
        self.phases = phases
        self.phase_params = []

        for phase in phases:
            self.phase_params += [param for param in phase.req_params + phase.opt_params]


    def _makeRun(self):
        """
        Write code to run phases in Run() function
        """
        run = ""

        for phase in self.phases:
            phase_params = ["self." + param for param in self.phase_params]
            params = ", ".join(phase_param for phase_param in phase_params)
            run += "{} = {}(True, {})\n\t{}.Execute()\n\t".format(phase.name, phase.class_name, params, phase.name)

        return run

    def _makeSetup(self):
        """
        Write code to check if required params exist within model

        Somehow use GlobalParams to typeface and check args
        """
        return "return True"


    def _makeInit(self):
        """
        Make init function
        """

        init = ""

        for param in self.phase_params:
            init += "self.{0} = model.get('{0}')\n\t".format(param)

        return init
