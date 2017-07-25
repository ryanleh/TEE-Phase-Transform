"""
    A module that scans a host for open ports and returns a list of ports
    Implements Runner

"""
import nmap
import logging
from abstract_circadence_phase import AbstractCircadencePhase

class HostPortScan(AbstractCircadencePhase):
    TrackerId = 'HostPortScan'
    Subject = 'nmap_port_scanning_phase'
    Description =   """
                    This phase executes an nmap scan and returns all open
                    ports along with services on those ports
                    """
    
    required_input_parameters = {'RHOST': None, 'search_start': None, 'search_end': None}
    output_parameters = {'ports': None}

    def __init__(self, info=None):
        """
            Initialize the host port scanner object.
            @param options: a dict of module specific settings:
                ip address, log_name, and port search range
        """
        AbstractCircadencePhase.__init__(self, info=info)

        assert 'RHOST' in info
        assert 'search_start' in info
        assert 'search_end' in info

    def Setup(self):
        """
            Initialize Phase arguments, must return True
        """        
        self._rhost = self.PhaseResult['RHOST']
        self._search_start = self.PhaseResult['search_start']
        self._search_end = self.PhaseResult['search_end']

        self._extra_args = ''
        if 'additional_nmap_args' in self.PhaseResult:
            self._extra_args = self.PhaseResult['additional_nmap_args']
        return True


    def Run(self):
        """
            Start scanning a host
            Finishes with status, exit code, and list of ports
        """
        nm = nmap.PortScanner()
        nm.scan(self._rhost, self._search_start + '-' + self._search_end)
        ports_list = list()
        try:
            ports_list = list((nm[self._rhost]['tcp'].keys()))
        except KeyError:
            self._log.error('No ports found for host: %s', self._rhost)

        self._progress = 100
        self.PhaseResult.Info('Found {0} ports'.format(len(ports_list)))
        self.PhaseResult['ports'] = ports_list
        return True


def create(info=None):
    """
        Create a new instance of the host port scanner object.
        :return: instance of the scanner object
    """
    return HostPortScan(info)
