"""
    A module that scans a host for open ports and returns a list of ports
    Implements Runner

"""
import nmap
import logging
from abstract_circadence_phase import AbstractCircadencePhase

class HostPortScan(AbstractCircadencePhase):
    TrackerId = "PHS-e79ea5e8-5aac-11e7-b3e3-000c29c2ba76"
    Subject = "nmap_port_scanning_phase"
    Description =   """
                    This phase executes an nmap scan and returns all open
                    ports along with services on those ports
                    """
    
    required_input_parameters = {'RHOSTS': None, 'search_start': None, 'search_end': None, 'desired_port': None}
    optional_input_parameters = {'additional_nmap_args':""}
    output_parameters = {'port_list': None, 'RHOSTS': None}

    def __init__(self, info):
        """
            Initialize the host port scanner object.
            @param options: a dict of module specific settings:
                ip address, log_name, and port search range
        """
        AbstractCircadencePhase.__init__(self, info=info)

        assert 'RHOSTS' in info
        assert 'search_start' in info
        assert 'search_end' in info

    def Setup(self):
        """
            Initialize Phase arguments, must return True
        """        
        self._rhosts = self.PhaseResult['RHOSTS']
        self._search_start = self.PhaseResult['search_start']
        self._search_end = self.PhaseResult['search_end']

        self._extra_args = ''
        if 'additional_nmap_args' in self.PhaseResult:
            self._extra_args = self.PhaseResult['additional_nmap_args']
        if 'desired_port' in self.PhaseResult:
            self._desired_port = int(self.PhaseResult['desired_port'])

        return True


    def Run(self):
        """
            Start scanning a host
            Finishes with status, exit code, and list of ports
        """
        nm = nmap.PortScanner()
        ports_list = {}

        for host in self._rhosts:
            nm.scan(host, self._search_start + '-' + self._search_end)
            try:
                ports_list[host] = nm[host]['tcp'].keys()
                self.PhaseReporter.Info('Found {0} ports active on {1}'.format(len(ports_list), host))
            except KeyError:
                self.PhaseReporter.Info('No ports found for host: {}'.format(host))


        ips = []

        if self._desired_port:
            for ip in ports_list:
                print(ip)
                for port in ports_list[ip]:
                    if port == self._desired_port:
                        self.PhaseReporter.Info('Desired port {} found on {}'.format(self._desired_port,ip))
                        ips.append(ip)

        self.PhaseResult['RHOSTS'] = ips
        self.PhaseResult['port_list'] = ports_list

        self._progress = 100

        return True


def create(info):
    """
        Create a new instance of the phase
    """
    return HostPortScan(info)
