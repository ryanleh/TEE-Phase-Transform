from ai_utils.phases.persistence_through_registry import PersistenceThroughRegistryPhaseClass
from ai_utils.ai_logging.simplelogger import AiLoggerClass
import unittest


class TestPersistenceThroughRegistryPhaseClass(unittest.TestCase):

  def setUp(self):
    AiLoggerClass().Enable()

  def test_valid_parameters_with_short_root_key(self):
    phase = PersistenceThroughRegistryPhaseClass(True, 'hkcu', 'Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'AttackIQAutorunValue1', 'AttackIQAutorunData1')
    success = phase.Execute()
    self.assertTrue(success)

  def test_valid_parameters_long_short_root_key_upper(self):
    phase = PersistenceThroughRegistryPhaseClass(True, 'HKCU', 'Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'AttackIQAutorunValue1', 'AttackIQAutorunData1')
    success = phase.Execute()
    self.assertTrue(success)

  def test_valid_parameters_long_short_root_key(self):
    phase = PersistenceThroughRegistryPhaseClass(True, 'HKEY_CURRENT_USER', 'Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'AttackIQAutorunValue1', 'AttackIQAutorunData1')
    success = phase.Execute()
    self.assertTrue(success)

  def test_valid_parameters_long_short_root_key_lower(self):
    phase = PersistenceThroughRegistryPhaseClass(True, 'hkey_current_user', 'Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'AttackIQAutorunValue1', 'AttackIQAutorunData1')
    success = phase.Execute()
    self.assertTrue(success)

  def test_valid_parameters_case_insensitive_key(self):
    phase = PersistenceThroughRegistryPhaseClass(True, 'hkey_current_user', 'soFtware\\Microsoft\\WiNdows\\CurrentVersion\\Run', 'AttackIQAutorunValue1', 'AttackIQAutorunData1')
    success = phase.Execute()
    self.assertTrue(success)

  @unittest.SkipTest  # in the runner this test succeeds because it is executed with admin privs
  def test_key_creation_without_privileges(self):
    phase = PersistenceThroughRegistryPhaseClass(True, 'HKEY_LOCAL_MACHINE', 'Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'AttackIQAutorunValue1', 'AttackIQAutorunData1')
    success = phase.Execute()
    self.assertFalse(success)

  def test_invalid_key_creation(self):
    phase = PersistenceThroughRegistryPhaseClass(True, 'HKEY_CURRENT_USER', '\\\\\\InvalidKey\\Microsoft\\Windows\\CurrentVersion\\Run', 'AttackIQAutorunValue1', 'AttackIQAutorunData1')
    success = phase.Execute()
    self.assertFalse(success)

  def test_invalid_root_key(self):
    phase = PersistenceThroughRegistryPhaseClass(True, 'BAD', 'Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'AttackIQAutorunValue1', 'AttackIQAutorunData1')
    success = phase.Execute()
    self.assertFalse(success)

  def test_empty_root_key(self):
    phase = PersistenceThroughRegistryPhaseClass(True, '', 'Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'AttackIQAutorunValue1', 'AttackIQAutorunData1')
    success = phase.Execute()
    self.assertFalse(success)

  def test_empty_key(self):
    phase = PersistenceThroughRegistryPhaseClass(True, 'HKEY_CURRENT_USER', '', 'AttackIQAutorunValue1', 'AttackIQAutorunData1')
    success = phase.Execute()
    self.assertFalse(success)

  def test_empty_data(self):
    phase = PersistenceThroughRegistryPhaseClass(True, 'HKEY_CURRENT_USER', 'Software\\Microsoft\\Windows\\CurrentVersion\\Run', '', 'AttackIQAutorunData1')
    success = phase.Execute()
    self.assertFalse(success)

  def test_empty_value(self):
    phase = PersistenceThroughRegistryPhaseClass(True, 'HKEY_CURRENT_USER', 'Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'AttackIQAutorunValue1', '')
    success = phase.Execute()
    self.assertFalse(success)
