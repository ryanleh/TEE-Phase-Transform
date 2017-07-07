

"""
Build main.py based on phase objects

Make naming consistent?  Also, not implementing optional and required parameters + critical phase...fix

-setup could help decide how the class will be called based on which args are there

also put in a break if args aren't there
"""
class Main(object):
    def __init__(self, subject, type, description, phases):

        # TODO: make a generating tid
        self.tid = '123'
        self.subject = subject
        self.type = type
        self.description = description
        self.phases = phases


    def _makeRun(self):
        """
        Write code to run phases in Run() function
        """
        run = ""

        # TODO:More elegant tab solution
        for phase in self.phases:
            phase_params = ["self." + param for param in phase.req_params + phase.opt_params]
            params = ", ".join(phase_param for phase_param in phase_params)
            run += "{} = {}(True, {})\n        {}.Execute()\n        ".format(phase.name, phase.class_name, params, phase.name)

        return run

    def _makeSetup(self):
        """
        Write code to check if required params exist within model
        """
        return "return True"

    def _makeInit(self):
        """
        Make init function
        """

        init = ""
        phase_params = []

        for phase in self.phases:
            phase_params += [param for param in phase.req_params + phase.opt_params]

        for param in phase_params:
            init += "self.{0} = model.get('{0}')\n        ".format(param)

        return init