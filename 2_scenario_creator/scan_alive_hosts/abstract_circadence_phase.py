"""
    Interface to abstract Circadence exploit modules
"""
from ai_utils.phases.abstract_phase import AbstractPhaseClass


class AbstractCircadencePhase(AbstractPhaseClass):
    """
        Base class for Circadence phases.
        @requires:  C{TrackerId},
                    C{Subject},
                    C{Description} attributes
    """
    TrackerId = 'AbstractCircadencePhase'
    Subject = 'AbstractCircadencePhase'
    Description =   """
                    AbstractCircadencePhase is the base class for all
                    Circadence Exploit phases.
                    """

    required_input_parameters = {}
    optional_input_parameter = {}
    output_parameters = {}

    def __init__(self, isPhaseCritical=True, info=None):
        """
            Initialize the abstract Circadence phase.

            @precondition: Must take the input parameters C{isPhaseCritical}
                and C{info}

            @type isPhaseCritical: boolean
            @type info: dict

            @requires: Must call the C{__init__} method of the parent class
                C{AbstractPhaseClass}
        """
        AbstractPhaseClass.__init__(self, isPhaseCritical)
        if info is None or not isinstance(info, dict):
            info = {}
        self.PhaseResult = info
        self._progress = 0

    def Run(self):
        """
            Must override
            @return: True if exploit successful, False otherwise
        """
        raise NotImplementedError('Abstract method; Must be overridden')

    @classmethod
    def get_req_inputs(cls):
        """
            Return all required input parameters of the phase along
            with their default values if any.
        """
        return cls.required_input_parameters

    @classmethod
    def get_opt_inputs(cls):
        """
            Return all optional input parameters of the phase along
            with their default values if any.
        """
        return cls.optional_input_parameters

    @classmethod
    def get_outputs(cls):
        """
            Return all output parameters of the phase that are passed into
            the C{PhaseResult} dict.
        """
        return cls.output_parameters

    def get_progress(self):
        """
            Return a number between 0 and 100, inclusive indicating percent
            complete.

            @return: int in [0, 100]

            @requires: The subclass needs to set and update C{self._progress}
                while C{self.Run}, from the parent class, is doing its thing.
        """
        return self._progress

    def get_result(self):
        """
            Return dict of information with the results of the exploit.

            Probably you should also include in this dict all that was passed
            in the constructor as C{info}, either by value or by reference.
            Within an attack chain, one step's C{get_result()} should be enough
            for the next step's C{info}.

            @return: dict of information with the results
        """
        return self.PhaseResult
