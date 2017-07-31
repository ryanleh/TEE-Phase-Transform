"""
    This module runs after all of the ProFTPd 1.3.5 exploit is over and
    is responsible only for printing the exploit result.

    @requires: C{proftpd_1_3_5_rce_result}, a dictionary from hostname
        to 0 if the exploit succeeded and an error summary if otherwise.
"""
from abstract_circadence_phase import AbstractCircadencePhase


class proftpd_1_3_5_rce_report(AbstractCircadencePhase):
    TrackerId = 'proftpd_1_3_5_rce_report'
    Subject = 'print_results_of_proftp_exploit'
    Description =   """
                    The 'proftpd_1_3_5_rce_report' phase prints results
                    of the proftp exploit
                    """
    
    required_input_parameters = {'proftpd_1_3_5_rce_result': None}
    output_parameters = {}

    def __init__(self, info):
        """
            Initialize the ftp remote command execution post-attack reporter.
            @param info: a dictionary of a lot of important things
        """
        AbstractCircadencePhase.__init__(self, info=info)

    def Run(self):
        """
            Start the reporting.
        """
        if 'proftpd_1_3_5_rce_result' not in self.PhaseResult:
            raise KeyError('Missing key: proftpd_1_3_5_rce_result.')

        for host, result in self.PhaseResult['proftpd_1_3_5_rce_result'].items():
            if result == 0:
                self.PhaseReporter.Info('ProFTPd 1.3.5 RCE exploit on {0} succeeded'.format(host))
            else:
                 self.PhaseReporter.Info('ProFTPd 1.3.5 RCE exploit on {0} failed: {1}'.format(host, result))

        self._progress = 100
        return True


def create(info):
    """
        Create a new instance of the host port scanner object.
        @param info: initialization dictionary
        @return instance of the scanner object
    """
    return proftpd_1_3_5_rce_report(info)
