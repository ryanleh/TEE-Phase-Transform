"""
    An example exploit module that demonstrated the module interface.

    The exploitrix framework requires this module to have init, start,
    progress, and result functions.

"""
import time
from abstract_circadence_phase import AbstractCircadencePhase


class Example(AbstractCircadencePhase):
    TrackerId = 'Example'
    Subject = 'Example'
    Description =   """
                    Example phase
                    """
    
    required_input_parameters = {}
    output_parameters = {}

    def __init__(self, info=None):
        """
            Initialize the exploit.
            @param info: a dict of module specific settings
        """
        AbstractCircadencePhase.__init__(self, info=info)
        # Other initialization goes here

    def Run(self):
        """
            Execute the stage.  Return when complete.
            @precondition: state 
            @postcondition: state contains 'time'
        """
        while self._progress < 100:
            time.sleep(0.01)
            self._progress += 1
        self.PhaseResult['time'] = time.time()
        return True


def create(info=None):
    """
        Create a new instance of the stage object.
        @return: instance of the stage object
    """
    return Example(info)
