from ai_utils.phases.ingress_port_checker import IngressPortCheckerPhaseClass
from ai_utils.ai_logging.simplelogger import AiLoggerClass
from random import randint
import unittest
import logging


class TestIngressPortCheckerPhaseClass(unittest.TestCase):

  INGRESS_HOSTS_OPEN_PORTS = {
    'http://google.com': '80,443',
    '8.8.4.4': '53, 443'
  }

  def setUp(self):
    AiLoggerClass(loggingLevel=logging.DEBUG).Enable()

  # NOTE: This test will fail if you don't correctly set firewall policies to not block any traffic to all ports
  @unittest.skip
  def test_run_correct_parameters(self):
    logging.info('Executing test_run_correct_parameters...')
    ingress_host = self._get_random_ingress_host()
    valid_port_list = self._get_valid_port_string(ingress_host)
    ipcpc = IngressPortCheckerPhaseClass(True, ingress_host, valid_port_list)
    critical_success = ipcpc.Execute()
    self.assertTrue(critical_success, 'Ingress Port checker with valid parameters has failed.')

  def test_run_with_empty_ports_parameter(self):
    logging.info('Executing test_run_with_empty_ports_parameter...')
    valid_port_list = ''
    ingress_host = self._get_random_ingress_host()
    ipcpc = IngressPortCheckerPhaseClass(True, ingress_host, valid_port_list)
    critical_success = ipcpc.Execute()
    self.assertFalse(critical_success, 'Ingress Port checker with empty parameters has failed (no ports).')

  def test_run_with_empty_host_parameter(self):
    logging.info('Executing test_run_with_empty_host_parameter...')
    valid_port_list = self._get_valid_port_string()
    ingress_host = ''
    ipcpc = IngressPortCheckerPhaseClass(True, ingress_host, valid_port_list)
    critical_success = ipcpc.Execute()
    self.assertFalse(critical_success, 'Ingress Port checker with empty parameters has failed (no host).')

  def test_run_invalid_ports_parameter(self):
    logging.info('Executing test_run_invalid_ports_parameter...')
    invalid_port_list = 'thisisnotaport'
    ingress_host = self._get_random_ingress_host()
    ipcpc = IngressPortCheckerPhaseClass(True, ingress_host, invalid_port_list)
    critical_success = ipcpc.Execute()
    self.assertFalse(critical_success, 'Ingress Port checker with invalid parameters has failed (bad ports).')

  def test_run_invalid_remote_host(self):
    logging.info('Executing test_run_invalid_remote_host...')
    invalid_port_list = self._get_valid_port_string()
    ingress_host = 'this_is_not_a_valid_host'
    ipcpc = IngressPortCheckerPhaseClass(True, ingress_host, invalid_port_list)
    critical_success = ipcpc.Execute()
    self.assertFalse(critical_success, 'Ingress Port checker with invalid parameters has failed (bad host).')

  def test_setup_timeout(self):
    valid_timeouts = ['1ms', '60m', '3h']
    invalid_timeouts = ['-1ms', '60ma', '3uh', '-1mss', '1mss', None, '']
    valid_port_list = self._get_valid_port_string()
    ingress_host = self._get_random_ingress_host()
    for timeout in valid_timeouts:
      ipcpc = IngressPortCheckerPhaseClass(True, ingress_host, valid_port_list, timeout=timeout)
      self.assertEqual(ipcpc.timeout, timeout)
    for timeout in invalid_timeouts:
      ipcpc = IngressPortCheckerPhaseClass(True, ingress_host, valid_port_list, timeout=timeout)
      self.assertEqual(ipcpc.timeout, '120m')

  def test_get_valid_ports(self):
    logging.info('Executing test_get_valid_ports...')
    valid_port_expressions = {
      '': [],
      '80,53': [80, 53],
      '80,53, 52': [80, 53, 52],
      '80,53, 53': [80, 53, 53],
      '53-60': [53, 54, 55, 56, 57, 58, 59, 60],
      '1024-1026,80,40': [1024, 1025, 1026, 80, 40],
      '1024-1026,80,40-42': [1024, 1025, 1026, 80, 40, 41, 42],
      '1,,2': [1, 2],
      '-': [port for port in range(1, 65535 + 1)]
    }
    invalid_port_expressions = {
      '60-40': None,
      '-1': None,
      '1,2,-1': [1, 2],
      '1,2,60-40': [1, 2],
      '1,2,60--1': [1, 2],
      '1,2,60-60': [1, 2],
      '1,2,60-60,5,8-10': [1, 2, 5, 8, 9, 10],
      '-1-30': None,
      '0': None,
      '1,nondigit': None
    }
    for port_expressions in [valid_port_expressions, invalid_port_expressions]:
      for port_expression, expected_value in port_expressions.iteritems():
        ipcpc = IngressPortCheckerPhaseClass(True, self._get_random_ingress_host(), port_expression)
        self.assertEqual(ipcpc.list_of_valid_ports, expected_value)

  def _get_valid_port_string(self, host=None):
    ports = "-"
    if host is not None:
      ports = self.INGRESS_HOSTS_OPEN_PORTS.get(host, ports)
    return ports

  def _get_random_ingress_host(self):
    return self.INGRESS_HOSTS_OPEN_PORTS.keys()[randint(0, len(self.INGRESS_HOSTS_OPEN_PORTS.keys()) - 1)]
