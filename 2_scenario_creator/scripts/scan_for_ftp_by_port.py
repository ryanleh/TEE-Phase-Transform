"""
    A module that scans for all FTP hosts in given a list of nmap targets. We
    accomplish this by searching for hosts with TCP port 21 open.

    @requires: A list of nmap targets.
"""
from abstract_circadence_phase import AbstractCircadencePhase
import nmap

class scan_for_ftp_by_port(AbstractCircadencePhase):
    TrackerId = 'scan_for_ftp_by_port'
    Subject = 'nmap_scan_for_open_ftp_hosts'
    Description =   """
                    The 'scan_for_ftp_by_port' phase uses nmap to scan
                    for live hosts with the default ftp port open, port 21.
                    """

    required_input_parameters = {'network_targets': None}
    output_parameters = {'hosts': None}

    def __init__(self, info):
        """
            Initialize the ftp host finder.
            @requires: C{info} has to have a key C{network_targets}
                that we will search for FTP hosts. C{network_targets}
                has to be a list of strings that specify targets in
                nmap's format.

            >>> scan_for_ftp_by_port({'network_targets': ['192.168.10.0/24']})
        """
        AbstractCircadencePhase.__init__(self, info=info)
        self._network_targets = info['network_targets']
        assert 'network_targets' in info

    def Run(self):
        """
            Start scanning a host
            Finishes with status, exit code, and list of ports
        """
        hosts = set()
        for scan_target in self._network_targets:
            # Maybe there's a better way to use nmap but this is fiiiine
            # (probably)
            nm = nmap.PortScanner()
            # look if 21 is open; if so it might be FTP ehh
            nm.scan(scan_target, '21')
            hosts.update(host for host in nm.all_hosts() if nm[host]['tcp'][21]['state'] == 'open')

        self._progress = 99

        # Now to get hosts into the dictionary
        self.PhaseResult['hosts'] = list(hosts)
        self._progress = 100
        return True


def create(info):
    """
        Create a new instance of the host port scanner object.
        @param info: Initialization dictcionary
        @return instance of the scanner object
    """
    return scan_for_ftp_by_port(info)
