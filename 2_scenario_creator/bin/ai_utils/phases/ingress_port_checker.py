from ai_utils.utils.networkutils import NetworkUtilsClass as NetworkUtils
from ai_utils.utils.offensive.nmap_utils.nmap import NmapUtilsClass
from ai_utils.utils.offensive.nmap_utils.port_parser import PortParser
from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.ai_logging.simplelogger import AiLoggerClass
import logging
import time
import re


class IngressPortCheckerPhaseClass(AbstractPhaseClass):
    TrackerId = "474"
    Subject = "Ingress Port Checker"
    Description = "This phase checks if the policies for ingress ports are correctly enforced on remote host."

    def __init__(self, is_phase_critical, host, valid_ports_string, timeout='120m'):
        """
        By using this phase the ingress network configuration of a remote system can be validated. This phase allows to
        identify what are the rules implemented to define ingress communication to different online services that should
        have all the ports open at the remote system from the asset where the phase is executed .

        This phase will be successful if the believed open or closed ports are, in fact, open or closed.

        In order to determine if the phase is successful, nmap will be used to scan selected ports in the remote host
        specified by the `host` variable. The asset must have all outgoing ports open. The `valid_ports_string` variable
        defines all the egress ports that are believed to be open in the remote system where the phase is executed. All
        remaining ports are believed to be closed. If the ingress communication policy of the firewall is not the expected,
        nmap will identify a believed open port to be closed or otherwise, if that is the case, the phase will fail.

        Args:
          is_phase_critical: Identify if the phase is critical. If it is critical, its outcome will be taken into account
          to define the overall scenario outcome.
          host: Remote server which ports will be tested. It can be an IP or a hostname.
          valid_ports_string: An nmap expression to define ports. E.g. "1,2", "1,2,100-2000", "20-50, 53, 22, 1024-50000"
          timeout: String defining the maximum time the scan can take. E.g: "1m", "2h", "5000ms". Default value: 120m

        Returns: True if the phase is successful, False otherwise
        """
        logging.debug('Executing IngressPortCheckerPhaseClass constructor. is_phase_critical:{} host:{} valid_ports_string:{} timeout:{}'.format(is_phase_critical, host, valid_ports_string, timeout))
        AbstractPhaseClass.__init__(self, is_phase_critical)
        AiLoggerClass(loggingLevel=logging.DEBUG).Enable()
        self.number_of_ports = 65535
        self.host = self.setup_host(host)
        self.valid_ports_string = self.setup_valid_ports_string(valid_ports_string)
        self.list_of_valid_ports = self.get_valid_ports(valid_ports_string)
        self.list_of_invalid_ports = self.get_invalid_ports()
        self.timeout = self.setup_timeout(timeout)
        self.task = ''
        self.percentage = ''
        self.open_ports_that_should_be_closed = set()
        self.closed_ports_that_should_be_opened = set()

    def Setup(self):
        logging.debug('Executing Setup')
        if not self.host:
            self.PhaseReporter.Error('A Host for checking ingress ports is required')
            return False
        if not self.valid_ports_string:
            self.PhaseReporter.Error('Valid Ports parameter is required')
            return False
        if not isinstance(self.list_of_valid_ports, list):
            self.PhaseReporter.Error('A list of valid ports could not be computed. Phase will fail')
            return False
        if not isinstance(self.list_of_invalid_ports, list):
            self.PhaseReporter.Error('A list of invalid ports could not be computed. Phase will fail')
            return False
        return True

    def Run(self):
        logging.debug('Executing Run')
        phase_successful = self.execute_phase()
        self.log_phase_result(phase_successful)
        return phase_successful

    def execute_phase(self):
        logging.debug('Executing execute_phase')
        phase_successful = False
        try:
            start = time.time()
            real_open_ports = NmapUtilsClass.GetOpenTCPPorts([self.host], ports='1-65535', callback=self.ingress_callback, timeout=self.timeout)
            end = time.time()
            logging.debug('Checking valid ports took {:.2f} minutes. If this value is greater than the timeout ({}), the scan results might not be correct'.format((end - start) / 60, self.timeout))
            self.PhaseReporter.Info('Nmap scan used to identify open and closed ports took {:.2f} minutes'.format((end-start)/60))
            phase_successful = self.check_results(real_open_ports)
        except Exception as e:
            self.PhaseReporter.Error('An unexpected error occurred while scanning ports: {0}'.format(e))
        return phase_successful

    def ingress_callback(self, nmap_process_object):
        logging.debug('Executing ingress_callback. nmap_process_object: {}'.format(nmap_process_object))
        if nmap_process_object.is_running() and nmap_process_object.current_task:
            nmap_task = nmap_process_object.current_task
            if nmap_task.name != self.task:  # only print if task is different than previous
                self.task = nmap_task.name
                self.percentage = nmap_task.progress
                logging.debug("{0}: {1}%".format(nmap_task.name, nmap_task.progress))
            else:  # if task is not different than previous, only print if percentage is different than previous
                if nmap_task.progress != self.percentage:
                    self.percentage = nmap_task.progress
                    logging.debug("{0}: {1}%".format(nmap_task.name, nmap_task.progress))

    def check_results(self, real_open_ports):
        logging.debug('Executing check_results. real_open_ports: {}'.format(real_open_ports))
        success = False
        if real_open_ports:
            success = self.compute_port_configuration(real_open_ports)
        else:
            self.PhaseReporter.Error('Host was not available')
        return success

    def compute_port_configuration(self, real_open_ports):
        logging.debug('Executing compute_port_configuration. real_open_ports: {}'.format(real_open_ports))
        all_ports = range(1, self.number_of_ports + 1)
        set_of_valid_ports = set(self.list_of_valid_ports)
        set_of_invalid_ports = set(self.list_of_invalid_ports)
        set_of_real_open_ports = set(real_open_ports[0][1])
        set_of_real_closed_ports = set(all_ports) - set_of_real_open_ports

        self.open_ports_that_should_be_closed = set_of_real_open_ports - set_of_valid_ports
        self.closed_ports_that_should_be_opened = set_of_real_closed_ports - set_of_invalid_ports

        self.log_open_ports(set_of_real_open_ports, len(set_of_real_open_ports))
        return not (self.open_ports_that_should_be_closed or self.closed_ports_that_should_be_opened)

    @staticmethod
    def log_open_ports(open_ports, number_of_open_ports):
        logging.debug('Executing log_open_ports. open_ports: {}(...), number_of_open_ports: {}'.format(list(open_ports)[:10], number_of_open_ports))
        if number_of_open_ports <= 50 and number_of_open_ports != 0:
            logging.debug('{} open ports found: {}'.format(number_of_open_ports, open_ports))
        else:
            logging.debug('{} open ports found'.format(number_of_open_ports))

    @staticmethod
    def setup_host(host):
        logging.debug('Executing setup_host. host: {}'.format(host))
        if host.find('http://') != -1:
            param = host.replace('http://', '')
        elif host.find('https://') != -1:
            param = host.replace('https://', '')
        else:
            param = host
        logging.debug('Host parameter: {0}'.format(param))
        return param

    def setup_valid_ports_string(self, valid_ports_string):
        logging.debug('Executing setup_valid_ports_string. valid_ports_string: {}'.format(valid_ports_string))
        param = ''
        if self.match_valid_ports_regex(valid_ports_string):
            param = valid_ports_string
        else:
            self.PhaseReporter.Error('Ports parameter can only contain digits, spaces, commas and dashes. Current value: {}'.format(valid_ports_string))
        logging.debug('Valid Ports parameter: {0}'.format(param))
        return param

    def setup_timeout(self, timeout):
        logging.debug('Executing setup_timeout. timeout: {}'.format(timeout))
        param = ''
        if timeout:
            param = self.parse_timeout(timeout)
        if not param:
            param = '120m'
            self.PhaseReporter.Warn('Timeout parameter was not correctly set. Using default value {}.'.format(param))
        logging.debug('Nmap timeout set to: {}'.format(param))
        return param

    def parse_timeout(self, timeout):
        logging.debug('Executing parse_timeout. timeout: {}'.format(timeout))
        param = None
        number, unit = self.parse_number_and_unit_from_timeout(timeout)
        if number and unit:
            param = '{}{}'.format(number, unit)
        return param

    def parse_number_and_unit_from_timeout(self, timeout):
        logging.debug('Executing parse_number_and_unit_from_timeout. timeout: {}'.format(timeout))
        number, unit = None, None
        try:
            number = int(re.search(r'\d+', timeout.strip()).group())
            unit = re.search(r'\D+', timeout.strip()).group().lower()
            if not (unit == 'ms' or unit == 's' or unit == 'm' or unit == 'h'):
                self.PhaseReporter.Warn('Timeout parameter is not in the correct format. Valid examples: {}. Received: {}'.format('1m, 1000ms, 2h', timeout))
                unit = None
        except:
            self.PhaseReporter.Warn('Timeout parameter is not in the correct format. Valid examples: {}. Received: {}'.format('1m, 1000ms, 2h', timeout))
        return number, unit

    def get_valid_ports(self, valid_ports_string):
        logging.debug('Executing get_valid_ports. valid_ports_string: {}'.format(valid_ports_string))
        param = PortParser(self.PhaseReporter).parse_ports(valid_ports_string)
        if type(param) == list:
            value = '{}(...)' if param else '{}'
            value = value.format(', '.join(str(port) for port in param[:10]) if param else '(No valid ports)')
            logging.debug('Validating that only the following ports are open: {0}'.format(value))
        else:
            self.PhaseReporter.Error('Port parameter could not be parsed. Ports parameter can only contain digits, spaces, commas and dashes. Current value: {}'.format(valid_ports_string))
        return param

    def get_invalid_ports(self):
        logging.debug('Executing get_invalid_ports')
        invalid_ports = range(1, self.number_of_ports + 1)
        if self.list_of_valid_ports:
            for valid_port in self.list_of_valid_ports:
                try:
                    invalid_ports.remove(valid_port)
                except ValueError:
                    pass  # ValueError exception is thrown when user inputs repeated ports in the port expression. e.g. 80,20,20
        return invalid_ports

    def log_phase_result(self, success):
        logging.debug('Executing log_phase_results. success: {}'.format(success))
        if success:
            self.PhaseReporter.Report('Ingress port security check was successful. All ports are correctly filtered in the remote host')
        else:
            self.log_detected_port_missconfigurations()

    def log_detected_port_missconfigurations(self):
        logging.debug('Executing log_phase_conclusions. open_ports_that_should_be_closed: {}(...), closed_ports_that_should_be_opened: {}(...)'.format(list(self.open_ports_that_should_be_closed)[:10], list(self.closed_ports_that_should_be_opened)[:10]))
        if self.open_ports_that_should_be_closed:
            port_ranges = NetworkUtils.GeneratePortRanges(self.open_ports_that_should_be_closed)
            self.PhaseReporter.Report('The following {} ingress ports are open but they should have been closed: {}'.format(len(self.open_ports_that_should_be_closed), ', '.join(map(str, port_ranges))))
            self.PhaseReporter.Mitigation('Check your firewall configuration for closing the following ports: {}'.format(', '.join(map(str, port_ranges))))
        if self.closed_ports_that_should_be_opened:
            port_ranges = NetworkUtils.GeneratePortRanges(self.closed_ports_that_should_be_opened)
            self.PhaseReporter.Report('The following {} ingress ports are closed but they should have been open: {}'.format(len(self.closed_ports_that_should_be_opened), ', '.join(map(str, port_ranges))))
            self.PhaseReporter.Mitigation('Check your firewall configuration for opening the following ports: {}'.format(', '.join(map(str, port_ranges))))

    @staticmethod
    def match_valid_ports_regex(ports):
        logging.debug('Executing match_valid_ports_regex. ports: {}'.format(ports))
        if re.match('^[\d, -]*$', ports):
            return True
        return False

    def parse_ports(self, ports_string):
        logging.debug('Executing parse_ports. ports_string: {}'.format(ports_string))
        result = []
        if ',' in ports_string:  # it is a list of comma-separated ports
            for ports_block in ports_string.split(','):
                result += self.parse_single_port_or_range(ports_block)
        else:  # it is not a list of comma-separated ports
            result = self.parse_single_port_or_range(ports_string)
        if not self.check_port_list_correctness(result):
            self.PhaseReporter.Error('After being processed, port list is not valid. Given port expression is not correct.')
            result = []
        return result

    def parse_single_port_or_range(self, port_or_range):
        logging.debug('Executing parse_single_port_or_range. port_or_range: {}'.format(port_or_range))
        result = []
        port_or_range = port_or_range.strip()
        if '-' in port_or_range:  # port range
            result += self.parse_port_range(port_or_range)
        elif port_or_range.isdigit():  # single port
            result += [int(port_or_range)]
        else:
            logging.error('Symbol not a dash or number in a port or range variable ({0}). Wrong port format. Ignoring value.'.format(port_or_range))
        return result

    def parse_port_range(self, port_range):
        logging.debug('Executing parse_port_range. port_range: {}'.format(port_range))
        lower_and_upper_limits = [port.strip() for port in port_range.split('-')]
        if self.check_range_list_correctness(port_range):
            result = range(int(lower_and_upper_limits[0]), int(lower_and_upper_limits[1]) + 1)
        else:
            logging.error('Range expression is incorrect. Ignoring range: {0}'.format(port_range))
            result = []
        return result

    @staticmethod
    def check_range_list_correctness(port_range):
        logging.debug('Executing check_range_list_correctness. port_range: {}'.format(port_range))
        success = True
        lower_and_upper_limits = [port.strip() for port in port_range.split('-')]
        for item in lower_and_upper_limits:
            if not item.isdigit():
                return False
        if len(lower_and_upper_limits) != 2 or int(lower_and_upper_limits[0]) >= int(lower_and_upper_limits[1]):
            success = False
        return success

    def check_port_list_correctness(self, port_list):
        logging.debug('Executing check_port_list_correctness. port_list: {}'.format(port_list))
        success = True
        for port in port_list:
            if not isinstance(port, int) or port < 0 or port > self.number_of_ports:
                success = False
                break
        return success
