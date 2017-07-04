

"""
Phase object should have filename, classname, imports, required param, and optional
params as variables
"""
class PhaseParams(object):
    def __init__(self, phase_name):
    """
    Check if given phase exists
    """

    def _getImports(self):
    """
    Returns any imports outside of stdlib and ai_utils
    """

    def _getRequiredParams(self):
    """
    Returns mandatory Params requested by __init__ of phase
    """

    def _getOptionalParams(self):
    """
    Returns mandatory Params requested by __init__ of phase
    """

    def retrieveInfo(self):
    """
    Public function to retrieve all info
    """
