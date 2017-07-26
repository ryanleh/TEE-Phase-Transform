from ai_utils.phases.egress_port_checker import EgressPortCheckerPhaseClass
from ai_utils.ai_logging.simplelogger import AiLoggerClass
from random import randint
import unittest
import logging


class TestEgressPortCheckerPhaseClass(unittest.TestCase):

  EGRESS_CHECKING_SERVICES = [
    #'http://portquiz.net',
    'http://egadz.metasploit.com',
    'http://104.236.135.40'  # AttackIQ Egress Service
  ]

  def setUp(self):
    AiLoggerClass(loggingLevel=logging.DEBUG).Enable()

  # NOTE: This test will fail if you don't correctly set firewall policies to not block any traffic to all ports
  """  These two tests are disabled so the whole baterry of tests in our CI system do not take too long
  def test_run_correct_parameters(self):
    logging.info('Executing test_run_correct_parameters...')
    valid_port_list = self._get_valid_port_string()
    egress_checking_service_url = self._get_random_egress_checking_service_url()
    epcpc = EgressPortCheckerPhaseClass(True, egress_checking_service_url, valid_port_list)
    critical_succes = epcpc.Execute()
    self.assertTrue(critical_succes, 'Egress Port checker with valid parameters has failed.')

  def test_run_with_empty_ports_parameter(self):
    logging.info('Executing test_run_with_empty_ports_parameter...')
    valid_port_list = ''
    egress_checking_service_url = self._get_random_egress_checking_service_url()
    epcpc = EgressPortCheckerPhaseClass(True, egress_checking_service_url, valid_port_list)
    critical_succes = epcpc.Execute()
    self.assertFalse(critical_succes, 'Egress Port checker with empty parameters has failed (no valid ports).')
  """

  def test_run_with_empty_remote_url_parameter(self):
    logging.info('Executing test_run_with_empty_remote_url_parameter...')
    valid_port_list = self._get_valid_port_string()
    egress_checking_service_url = ''
    epcpc = EgressPortCheckerPhaseClass(True, egress_checking_service_url,valid_port_list)
    critical_succes = epcpc.Execute()
    self.assertFalse(critical_succes, 'Egress Port checker with empty parameters has failed (no valid services).')

  def test_run_invalid_ports_parameter(self):
    logging.info('Executing test_run_invalid_ports_parameter...')
    invalid_port_list = 'thisisnotaport'
    egress_checking_service_url = self._get_random_egress_checking_service_url()
    epcpc = EgressPortCheckerPhaseClass(True, egress_checking_service_url, invalid_port_list)
    critical_succes = epcpc.Execute()
    self.assertFalse(critical_succes, 'Egress Port checker with invalid parameters has failed (bad ports).')

  def test_run_invalid_remote_url_parameter(self):
    logging.info('Executing test_run_invalid_remote_url_parameter...')
    invalid_port_list = self._get_valid_port_string()
    egress_checking_service_url = 'this_is_not_a_correct_url'
    epcpc = EgressPortCheckerPhaseClass(True, egress_checking_service_url, invalid_port_list)
    critical_succes = epcpc.Execute()
    self.assertFalse(critical_succes, 'Egress Port checker with invalid parameters has failed (bad services).')

  def test_setup_timeout(self):
    valid_timeouts = ['1ms', '60m', '3h']
    invalid_timeouts = ['-1ms', '60ma', '3uh', '-1mss', '1mss', None, '']
    valid_port_list = self._get_valid_port_string()
    egress_checking_service_url = self._get_random_egress_checking_service_url()
    for timeout in valid_timeouts:
      epcpc = EgressPortCheckerPhaseClass(True, egress_checking_service_url, valid_port_list, timeout=timeout)
      self.assertEqual(epcpc.timeout, timeout)
    for timeout in invalid_timeouts:
      epcpc = EgressPortCheckerPhaseClass(True, egress_checking_service_url, valid_port_list, timeout=timeout)
      self.assertEqual(epcpc.timeout, '120m')

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
      '1,,2': [1,2],
      '-': [port for port in range(1, 65535+1)]
    }
    invalid_port_expressions = {
      '60-40': None,
      '-1': None,
      '1,2,-1': [1,2],
      '1,2,60-40': [1,2],
      '1,2,60--1': [1,2],
      '1,2,60-60': [1, 2],
      '1,2,60-60,5,8-10': [1, 2, 5, 8, 9, 10],
      '-1-30': None,
      '0': None,
      '1,nondigit': None
    }
    for port_expressions in [valid_port_expressions, invalid_port_expressions]:
      for port_expression, expected_value in port_expressions.iteritems():
        epcpc = EgressPortCheckerPhaseClass(True, self._get_random_egress_checking_service_url(), port_expression)
        self.assertEqual(epcpc.list_of_valid_ports, expected_value)

  def _get_valid_port_string(self):
    return '-'

  def _get_random_egress_checking_service_url(self):
    return self.EGRESS_CHECKING_SERVICES[randint(0, len(self.EGRESS_CHECKING_SERVICES)-1)]
