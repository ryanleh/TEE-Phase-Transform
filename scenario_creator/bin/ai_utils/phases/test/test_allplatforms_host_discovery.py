import logging
import unittest

from ai_utils.ai_logging.simplelogger import AiLoggerClass
from ai_utils.phases.host_discovery import HostDiscoveryPhaseClass
from ai_utils.scenarios.globals import NetworkUtils


class TestHostDiscoveryPhaseClass(unittest.TestCase):

  def setUp(self):
    AiLoggerClass(logging.DEBUG).Enable()

  def test_valid_parameters_found_forbidden_hosts(self):
    local_ip = NetworkUtils._GetLocalIPThroughRemoteConnection()
    phase = HostDiscoveryPhaseClass(True, ips_to_scan=[local_ip], expected_ips_up=[], timeout='')
    success = phase.Execute()
    self.assertTrue(success)

  def test_valid_parameters_no_forbidden_hosts(self):
    local_ip = NetworkUtils._GetLocalIPThroughRemoteConnection()
    phase = HostDiscoveryPhaseClass(True, ips_to_scan=[local_ip], expected_ips_up=[local_ip], timeout='')
    success = phase.Execute()
    self.assertFalse(success)

  def test_empty_ips_to_scan(self):
    phase = HostDiscoveryPhaseClass(True, ips_to_scan=[''], expected_ips_up=[])
    success = phase.Execute()
    self.assertFalse(success)

  def test_invalid_ips_to_scan(self):
    phase = HostDiscoveryPhaseClass(True, ips_to_scan=['invalid_ip'], expected_ips_up=[])
    success = phase.Execute()
    self.assertFalse(success)

  def test_invalid_expected_ips_up(self):
    local_ip = NetworkUtils._GetLocalIPThroughRemoteConnection()
    # Setting an invalid ip as expected ip is not be a problem
    phase = HostDiscoveryPhaseClass(True, ips_to_scan=[local_ip], expected_ips_up=['invalid_ip'])
    success = phase.Execute()
    self.assertTrue(success)

  def test_invalid_timeout(self):
    local_ip = NetworkUtils._GetLocalIPThroughRemoteConnection()
    phase = HostDiscoveryPhaseClass(True, ips_to_scan=[local_ip], expected_ips_up=[], timeout='-')
    success = phase.Execute()
    self.assertEqual(phase.timeout, '120m')
    self.assertTrue(success)