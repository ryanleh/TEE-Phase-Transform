#! /usr/bin/env python3
"""
    An example exploit module that uses the root shell on port 1524
    of a metasploitable2 host to exfil /etc/passwd and /etc/shadow.

    The exploitrix framework requires this module to have init, start,
    progress, and result functions.

"""
from abstract_circadence_phase import AbstractCircadencePhase


class MS2RootShell(Runner):
    TrackerId = 'MS2RootShell'
    Subject = 'MS2RootShell'
    Description =   """
                    The 'MS2RootShell' phase uses the root shell on
                    port 1542 of a metasploitable2 host to exfil
                    /etc/passwd and /etc/shadow.
                    """
    
    required_input_parameters = {'RHOST': None, 'RPORT': 1524}
    output_parameters = {}

    def __init__(self, info=None):
        """
            Initialize the exploit.
            @requires: The C{info} dict must have the keys 
                C{RHOST} and C{RPORT}
        """
        AbstractCircadencePhase.__init__(self, info=info)
        assert 'RHOST' in info
        assert 'RPORT' in info


    def Setup(self):
        self._rhost = self.PhaseResult['RHOST']
        self._port = self.PhaseResult['RPORT']
        return True


    def Run(self):
        """
            Execute the exploit.  Return when complete.
        """
        # Step One -- connect to the root shell
        # Step Two -- start a local socket to receive a file
        # Step Three -- execute netcat on the remote host to send /etc/passwd
        # Step Four -- start a local socket to receive a file
        # Step Five -- execute netcat on the remote host to send /etc/shadow
        # Step Six -- disconnect from remote host
        return True


def create(info):
    """
        Create a new instance of the exploit object.
        @param info: (required) with values for 'RHOST' and 'RPORT'
        @return: instance of the exploit object
    """
    return MS2RootShell(info)
