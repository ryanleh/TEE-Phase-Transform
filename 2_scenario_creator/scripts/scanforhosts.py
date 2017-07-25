"""
    A module that scans a network for hosts and returns a list of ip addresses
    Implements Runner
"""
from abstract_circadence_phase import AbstractCircadencePhase
import nmap
import logging

class ScanForHosts(AbstractCircadencePhase):
    TrackerId = 'ScanForHosts'
    Subject = 'scan_network_for_live_hosts'
    Description =   """
                    The 'ScanForHosts' phase uses nmap to scan for live
                    hosts on a network
                    """
    
    required_input_parameters = {'RHOST': None, 'mask': None}
    output_parameters = {}

    def __init__(self, info=None):
        """
            Initialize the host scanner object.
            @param info: a dict of module specific settings:
                RHOST, mask, log, and additional nmap arguments
        """
        AbstractCircadencePhase.__init__(self, info=info)
        assert 'RHOST' in info
        assert 'mask' in info

    def Setup(self):
        self._rhost = self.PhaseResult['RHOST']
        self._mask = int(self.PhaseResult['mask'])

        self._extra_args = ''
        if 'additional_nmap_args' in options:
            self._extra_args = options['additional_nmap_args']
        return True

    def Run(self):
        """
            Start scanning a network for active hosts
            Finishes with status, exit code, and list of ip addresses
        """
        nm = nmap.PortScanner()
        nm.scan(hosts=self._rhost + '/' + str(self._mask), arguments=self._extra_args)
        hosts_list = [x for x in nm.all_hosts() if nm[x]['status']['state'] == 'up']

        self._progress = 100
        self.PhaseReporter.Info('found {0} hosts'.format(len(hosts_list)))
        self.PhaseResult['hosts'] = hosts_list
        return True


def create(info=None):
    """
        Create a new instance of the host scanner object.
        @return: instance of the scanner object
    """
    return ScanForHosts(info)
