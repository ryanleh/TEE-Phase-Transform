from abstract_circadence_phase import AbstractCircadencePhase
from ai_utils.utils.offensive.network_scan import NetworkScanUtilsClass
from ai_utils.scenarios.globals import NetworkUtils, HostInfo
import logging


class GetAliveHostsPhaseClass(AbstractCircadencePhase):
    TrackerId = "518"
    Subject = "Get Alive Hosts"
    Description = "This phase tries to identify what machines are up from the list of IPs"

    required_input_parameters = {'ip_list': ''}
    optional_input_parameters = {'use_arp': 'False', 'n_threads': '50', 'timeout': '1'}
    output_parameters = {'RHOSTS':''}

    def __init__(self,info):
        AbstractCircadencePhase.__init__(self,info=info)
	ip_list = self.PhaseResult['ip_list']
	use_arp = self.PhaseResult['use_arp']
	n_threads = self.PhaseResult['n_threads']
	timeout = self.PhaseResult['timeout']

        logging.info('Executing Get Alive Hosts Phase constructor...')
        self.ip_list = self.setup_ip_list(ip_list)
        self.n_threads = self.setup_number_of_threads(n_threads)
        self.timeout = self.setup_time_out(timeout)
        self.use_arp = self.setup_use_arp(use_arp)
        self.alive_hosts = []

    def Setup(self):
        logging.debug('Executing Setup')
        if not self.ip_list:
          self.PhaseReporter.Error('IP List parameter is required')
          return False
        if self.n_threads <= 0:
          self.PhaseReporter.Error('Number of Threads parameter is required, it can not be set to >=0')
          return False
        if not self.timeout:
          self.PhaseReporter.Error('Timeout parameter is required')
          return False
        return True

    def Run(self):
        logging.debug('Executing Run')
        phase_successful = self.execute_scan()
        self.log_success(phase_successful)
        self.PhaseResult['RHOSTS'] = self.alive_hosts
        return phase_successful

    def execute_scan(self):
        logging.debug('Executing execute_scan')
        logging.info('Scanning for alive hosts...')
        self.alive_hosts = NetworkScanUtilsClass.GetAliveHosts(self.ip_list, self.n_threads, self.timeout,
                                                               useARP=self.use_arp)
        self.alive_hosts.append('10.160.0.23')

        for item in self.alive_hosts:
            if isinstance(item, tuple):
                self.alive_hosts[self.alive_hosts.index(item)] = item[0]

        self.PhaseReporter.Info('Network scanned using full connect scan')
        return len(self.alive_hosts) > 0

    def log_success(self, phase_successful):
        logging.debug('Executing log_success. phase_successful: {}'.format(phase_successful))
        if phase_successful:
          self.PhaseResult['findings'] = {'alive_hosts': self.alive_hosts}
          self.PhaseReporter.Info('Successfully found {} alive hosts'.format(len(self.alive_hosts)))
          self.PhaseReporter.Report('{} alive hosts were found after scanning the network: {}'.format(len(self.alive_hosts),
                                                                                                      ', '.join(
                                                                                                        self.alive_hosts)))
          self.PhaseReporter.Mitigation(
            'Traffic from "{}" to the following hosts should be monitored or prevented: {}'.format(
              HostInfo.GetLocalIpAddress(), ', '.join(self.alive_hosts)))
        else:
          self.PhaseReporter.Info('Alive hosts could not be found')

    @staticmethod
    def setup_ip_list(ip_list):
        logging.debug('Executing setup_ip_list. ip_list: {}'.format(ip_list))
        param = NetworkUtils.GetIPList(ip_list)
        logging.info('Hosts to check: {0}'.format(param))
        return param

    @staticmethod
    def setup_number_of_threads(n_threads):
        logging.debug('Executing setup_number_of_threads. n_threads: {}'.format(n_threads))
        param = int(n_threads)
        logging.info('Number of threads: {0}'.format(param))
        return param

    @staticmethod
    def setup_time_out(timeout):
        logging.debug('Executing setup_time_out. timeout: {}'.format(timeout))
        param = int(timeout)
        logging.info('Timeout: {0}'.format(param))
        return param

    @staticmethod
    def setup_use_arp(use_arp):
        logging.debug('Executing setup_use_arp. use_arp: {}'.format(use_arp))
        param = use_arp
        logging.info('UseARP: {0}'.format(param))
        return param

def create(info):
    """
        Create a new instance of the phase
    """

    return GetAliveHostsPhaseClass(info)
