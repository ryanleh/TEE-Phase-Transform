from ai_utils.utils.offensive.pass_the_hash.undetectable_mimikatz.undetectable_mimikatz_agent import UndetectableMimikatzAgent
from ai_utils.scenarios.globals import FileUtils
from ai_utils.ai_logging.simplelogger import AiLoggerClass
from copy import deepcopy
import unittest
import logging
import platform


class TestPTHUndetectableMimikatzAgent(unittest.TestCase):

  def setUp(self):
    AiLoggerClass(loggingLevel=logging.DEBUG).Enable()
    FileUtils.WriteToFile('mimikatz.exe', '')
    self.valid_params = {
      'password_hash': 'asdfghjkl',
      'target_machine': '127.0.0.1',
      'username': 'user',
      'fqdn': 'domainname',
      'remote_command_script': 'invalid_script_path',
      'command_log_path': 'invalid_log_path',
      'test_success_pattern': 'Pass the Hash Successful',
      'timeout': 30000,
      'phase_reporter': None
    }

  def test_all_valid_parameters(self):
    success = self._setup_pth(self.valid_params)
    self.assertTrue(success)

  def test_invalid_password_hash(self):
    invalid_params = deepcopy(self.valid_params)
    invalid_params['password_hash'] = ''
    success, _ = self._setup_pth(invalid_params)
    self.assertFalse(success)

  @unittest.skipIf(platform.platform() != 'Windows', 'This test only runs on Windows')
  def test_empty_target_machine(self):
    invalid_params = deepcopy(self.valid_params)
    invalid_params['target_machine'] = ''
    success, _ = self._setup_pth(invalid_params)
    self.assertTrue(success)

  def test_empty_username(self):
    invalid_params = deepcopy(self.valid_params)
    invalid_params['username'] = ''
    success, agent = self._setup_pth(invalid_params)
    self.assertTrue(success)
    self.assertEqual(agent.username, 'Administrator')

  @unittest.skipIf(platform.platform() != 'Windows', 'This test only runs on Windows')
  def test_empty_fqdn(self):
    invalid_params = deepcopy(self.valid_params)
    invalid_params['fqdn'] = ''
    success, _ = self._setup_pth(invalid_params)
    self.assertTrue(success)

  def test_empty_remote_command_script(self):
    invalid_params = deepcopy(self.valid_params)
    invalid_params['remote_command_script'] = ''
    success, _ = self._setup_pth(invalid_params)
    self.assertTrue(success)

  def test_empty_command_log_path(self):
    invalid_params = deepcopy(self.valid_params)
    invalid_params['command_log_path'] = ''
    success, _ = self._setup_pth(invalid_params)
    self.assertTrue(success)

  def test_empty_test_success_pattern(self):
    invalid_params = deepcopy(self.valid_params)
    invalid_params['test_success_pattern'] = ''
    success, agent = self._setup_pth(invalid_params)
    self.assertTrue(success)
    self.assertEqual(agent.test_success_pattern, 'Pass the Hash Successful')

  def test_empty_test_timeout(self):
    invalid_params = deepcopy(self.valid_params)
    invalid_params['timeout'] = None
    success, agent = self._setup_pth(invalid_params)
    self.assertTrue(success)
    self.assertEqual(agent.timeout, 30000)

  def test_empty_test_invalid_timeout(self):
    invalid_params = deepcopy(self.valid_params)
    invalid_params['timeout'] = -1
    success, agent = self._setup_pth(invalid_params)
    self.assertTrue(success)
    self.assertEqual(agent.timeout, 30000)

  def _setup_pth(self, params_dict):
    agent = UndetectableMimikatzAgent(**params_dict)
    return agent.setup_pth(), agent

  def tearDown(self):
    FileUtils.DeleteFile('mimikatz.exe')