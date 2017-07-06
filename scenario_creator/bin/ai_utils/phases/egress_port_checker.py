from ai_utils.utils.networkutils import NetworkUtilsClass as NetworkUtils
from ai_utils.utils.offensive.nmap_utils.nmap import NmapUtilsClass
from ai_utils.utils.offensive.nmap_utils.port_parser import PortParser
from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.ai_logging.simplelogger import AiLoggerClass
import logging
import time
import re


class EgressPortCheckerPhaseClass(AbstractPhaseClass):
  TrackerId = "464"
  Subject = "Egress Port Checker"
  Description = "This phase checks if outgoing traffic rules are correctly configured by trying to send outgoing " \
                "data using different ports"

  def __init__(self, is_phase_critical, egress_checking_service_url, valid_ports_string, timeout='120m'):
    """
    By using this phase the egress network configuration of an asset can be validated. This phase allows to identify
    what are the rules implemented to define egress communication from the asset where the phase is executed to
    different online services that should have all the ports open.

    This phase will be successful if the believed open or closed ports are, in fact, open or closed.

    In order to determine if the phase is successful, nmap will be used to scan all the ports in the host specified by
    the `egress_checking_service_url` variable. This host must have all the ports open. The `valid_ports_string`
    variable defines all the egress ports that are believed to be open in the asset where the phase is executed.
    All remaining ports are believed to be closed. If the egress communication policy of the firewall is not the
    expected, nmap will identify a believed open port to be closed or otherwise, if that is the case, the phase will
    fail.

    Args:
      is_phase_critical: Identify if the phase is critical. If it is critical, its outcome will be taken into account
      to define the overall scenario outcome.
      egress_checking_service_url: Remote server that should have all the ports open. It can be an IP or a hostname.
      valid_ports_string: An nmap expression to define ports. E.g. "1,2", "1,2,100-2000", "20-50, 53, 22, 1024-50000"
      timeout: String defining the maximum time the scan can take. E.g: "1m", "2h", "5000ms". Default value: 120m

    Returns: True if the phase is successful, False otherwise
    """
    logging.debug(Messages.INFO1)
    AbstractPhaseClass.__init__(self, is_phase_critical)
    AiLoggerClass(loggingLevel=logging.DEBUG).Enable()
    self.number_of_ports = 65535
    self.egress_checking_service_url = self.setup_egress_checking_service_url(egress_checking_service_url)
    self.list_of_valid_ports = self.get_valid_ports(valid_ports_string)
    self.list_of_invalid_ports = self.get_invalid_ports()
    self.timeout = self.setup_timeout(timeout)
    self.task = ''
    self.percentage = ''

  def Setup(self):
    logging.debug('Executing Setup')
    if not self.egress_checking_service_url:
      self.PhaseReporter.Error(Messages.ERROR1)
      return False
    if not type(self.list_of_valid_ports) == list:
      self.PhaseReporter.Error(Messages.ERROR2)
      return False
    if not type(self.list_of_invalid_ports) == list:
      self.PhaseReporter.Error(Messages.ERROR4)
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
      real_open_ports = NmapUtilsClass.GetOpenTCPPortsUsingFullConnectScan([self.egress_checking_service_url], ports='1-65535', timeout=self.timeout)
      end = time.time()
      logging.info(Messages.INFO5.format((end-start)/60, self.timeout))
      phase_successful = self.check_results(real_open_ports)
    except Exception as e:
      self.PhaseReporter.Error(Messages.ERROR8.format(e))
    return phase_successful

  def egress_callback(self, nmap_process_obj):
    logging.debug('Executing egress_callback. nmap_process_obj: {}'.format(nmap_process_obj))
    if nmap_process_obj.is_running() and nmap_process_obj.current_task:
      nmap_task = nmap_process_obj.current_task
      if nmap_task.name != self.task:  # only print if task is different than previous
        self.task = nmap_task.name
        self.percentage = nmap_task.progress
        logging.info("{0}: {1}%".format(nmap_task.name, nmap_task.progress))
      else:  # if task is not different than previous, only print if percentage is different than previous
        if nmap_task.progress != self.percentage:
          self.percentage = nmap_task.progress
          logging.info("{0}: {1}%".format(nmap_task.name, nmap_task.progress))

  def check_results(self, real_open_ports):
    logging.debug('Executing check_results. real_open_ports: {}'.format([(obj[0], '{}(...)'.format(', '.join([str(port) for port in obj[1][:10]])) ) for obj in real_open_ports]))
    success = False
    if real_open_ports:
      success = self.compute_port_configuration(real_open_ports)
    else:
      self.PhaseReporter.Error('Egress remote service was not available')
    return success

  def compute_port_configuration(self, real_open_ports):
    logging.debug('Executing compute_port_configuration. real_open_ports: {}(...)'.format(real_open_ports[:10]))
    all_ports = range(1, self.number_of_ports + 1)
    set_of_valid_ports = set(self.list_of_valid_ports)
    set_of_invalid_ports = set(self.list_of_invalid_ports)
    set_of_real_open_ports = set(real_open_ports[0][1])
    set_of_real_closed_ports = set(all_ports) - set_of_real_open_ports
    open_ports_that_should_be_closed = set_of_real_open_ports - set_of_valid_ports
    closed_ports_that_should_be_opened = set_of_real_closed_ports - set_of_invalid_ports
    self.log_open_ports(set_of_real_open_ports, len(set_of_real_open_ports))
    self.log_phase_conclusions(open_ports_that_should_be_closed, closed_ports_that_should_be_opened)
    return not (open_ports_that_should_be_closed or closed_ports_that_should_be_opened)

  def log_open_ports(self, open_ports, number_of_open_ports):
    logging.debug('Executing log_open_ports. open_ports: {}(...), number_of_open_ports: {}'.format(list(open_ports)[:10], number_of_open_ports))
    if number_of_open_ports <= 20 and number_of_open_ports != 0:
      logging.info(Messages.INFO9.format(number_of_open_ports, ','.join(map(str, open_ports))))
    else:
      logging.info(Messages.INFO10.format(number_of_open_ports))

  def log_phase_conclusions(self, open_ports_that_should_be_closed, closed_ports_that_should_be_opened):
    logging.debug('Executing log_phase_conclusions. open_ports_that_should_be_closed: {}(...), closed_ports_that_should_be_opened: {}(...)'.format(list(open_ports_that_should_be_closed)[:10], list(closed_ports_that_should_be_opened)[:10]))
    if open_ports_that_should_be_closed:
      port_ranges = NetworkUtils.GeneratePortRanges(open_ports_that_should_be_closed)
      self.PhaseReporter.Report(Messages.INFO7.format(len(open_ports_that_should_be_closed), ', '.join(map(str, port_ranges))))
      self.PhaseReporter.Mitigation(Messages.INFO13)
    if closed_ports_that_should_be_opened:
      port_ranges = NetworkUtils.GeneratePortRanges(closed_ports_that_should_be_opened)
      self.PhaseReporter.Report(Messages.INFO8.format(len(closed_ports_that_should_be_opened), ', '.join(map(str, port_ranges))))
      self.PhaseReporter.Mitigation(Messages.INFO13)

  def setup_egress_checking_service_url(self, egress_checking_service_url):
    logging.debug('Executing setup_egress_checking_service_url. egress_checking_service_url: {}'.format(egress_checking_service_url))
    if egress_checking_service_url.find('http://') != -1:
      param = egress_checking_service_url.replace('http://', '')
    elif egress_checking_service_url.find('https://') != -1:
      param = egress_checking_service_url.replace('https://', '')
    else:
      param = egress_checking_service_url
    logging.info(Messages.INFO4.format(param))
    return param

  def setup_timeout(self, timeout):
    logging.debug('Executing setup_timeout. timeout: {}'.format(timeout))
    param = ''
    if timeout:
      param = self.parse_timeout(timeout)
    if not param:
      self.PhaseReporter.Warn(Messages.WARN1)
      param = '120m'
    logging.info(Messages.INFO12.format(param))
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
        self.PhaseReporter.Warn(Messages.WARN2.format('1m, 1000ms, 2h', timeout))
        unit = None
    except:
      self.PhaseReporter.Warn(Messages.WARN2.format('1m, 1000ms, 2h', timeout))
    return number, unit

  def get_valid_ports(self, valid_ports_string):
    logging.debug('Executing get_valid_ports. valid_ports_string: {}'.format(valid_ports_string))
    param = PortParser(self.PhaseReporter).parse_ports(valid_ports_string)
    if type(param) == list:
      value = '{}(...)' if param else '{}'
      value = value.format(', '.join(str(port) for port in param[:10]) if param else '(No valid ports)')
      self.PhaseReporter.Info(Messages.INFO3.format(value))
    else:
      self.PhaseReporter.Error(Messages.ERROR3.format(valid_ports_string))
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
      self.PhaseReporter.Info(Messages.INFO2)
    else:
      self.PhaseReporter.Info(Messages.INFO6)


class Messages(object):
  INFO1 = 'Executing EgressPortCheckerPhaseClass constructor'
  INFO2 = 'Egress port security check was successful. All ports are correctly filtered'
  INFO3 = 'Validating that only the following ports are open: {0}'
  INFO4 = 'Egress Checking Service URL parameter: {0}'
  INFO5 = 'Checking valid ports took {:.2f} minutes. If this value is greater than the timeout ({}), the scan results might not be correct'
  INFO6 = 'Egress port security check failed. Port filtering might not be correctly configured'
  INFO7 = 'Your firewall is not configured as expected. The following {} egress ports are open but they should have been closed. Check your firewall configuration: {}'
  INFO8 = 'Your firewall is not configured as expected. The following {} egress ports are closed but they should have been open. Check your firewall configuration: {}'
  INFO9 = '{} open ports found: {}'
  INFO10 = '{} open ports found'
  INFO11 = 'Nmap binary set to: {}'
  INFO12 = 'Nmap timeout set to: {}'
  INFO13 = 'Review your firewall configurations to ensure that they reflect desired policies'

  WARN1 = 'Timeout parameter was not correctly set. Using default value 60m.'
  WARN2 = 'Timeout parameter is not in the correct format. Valid examples: {}. Received: {}'

  ERROR1 = 'A URL for checking egress ports is required. Phase will fail'
  ERROR2 = 'A list of valid ports could not be computed. Phase will fail'
  ERROR3 = 'Port parameter could not be parsed. Ports parameter can only contain digits, spaces, commas and dashes. Current value: {}'
  ERROR4 = 'A list of invalid ports could not be computed. Phase will fail'
  ERROR8 = 'An unexpected error occurred while scanning ports: {0}'
  ERROR9 = 'Nmap binary could not be found in the scenario bin folder. Phase will fail.'
  ERROR10 = 'Unable to determine operating system.'

