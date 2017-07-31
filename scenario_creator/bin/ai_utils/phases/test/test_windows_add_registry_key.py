from ai_utils.phases.add_registry_key import AddRegKeyAndValuePhaseClass
from ai_utils.utils.registryutils import RegistryUtils
import unittest


class TestAddRegKeyAndValuePhaseClass(unittest.TestCase):

    def setUp(self):
        self.registry_root = 'hkcu'
        self.registry_key = r'Environment'
        self.registry_subkey_name = 'NonExistingSubkey'
        self.registry_subkey_value = 'NonExistingValue'
        self.registry_subkey_data = 'NonExistingData'
        self.cleanup = True
    
    def test_valid_execution(self):
        add_registry_key_and_value = AddRegKeyAndValuePhaseClass(True, self.registry_root, self.registry_key, self.registry_subkey_name, self.registry_subkey_value, self.registry_subkey_data, self.cleanup)
        self.assertTrue(add_registry_key_and_value.Execute())
    
    def test_invalid_key(self):
        add_registry_key_and_value = AddRegKeyAndValuePhaseClass(True, self.registry_root,  '', self.registry_subkey_name, self.registry_subkey_value, self.registry_subkey_data, self.cleanup)
        self.assertFalse(add_registry_key_and_value.Execute())
    
    def test_invalid_subkey(self):
        add_registry_key_and_value = AddRegKeyAndValuePhaseClass(True, self.registry_root, self.registry_key, '', self.registry_subkey_value, self.registry_subkey_data, self.cleanup)
        self.assertFalse(add_registry_key_and_value.Execute())
    
    
    def test_invalid_data(self):
        add_registry_key_and_value = AddRegKeyAndValuePhaseClass(True, self.registry_root, self.registry_key, self.registry_subkey_name, self.registry_subkey_value, '', self.cleanup)
        self.assertFalse(add_registry_key_and_value.Execute())
    
    def test_invalid_cleanup(self):
        add_registry_key_and_value = AddRegKeyAndValuePhaseClass(True, self.registry_root, self.registry_key, self.registry_subkey_name, self.registry_subkey_value, self.registry_subkey_data, '')
        self.assertFalse(add_registry_key_and_value.Execute())
    
    def test_valid_key_creation(self):
        add_registry_key_and_value = AddRegKeyAndValuePhaseClass(True, self.registry_root, self.registry_key, self.registry_subkey_name, self.registry_subkey_value, self.registry_subkey_data, self.cleanup)
        add_registry_key_and_value.Setup()
        original_registry_subkey_exists, original_registry_data = RegistryUtils.get_subkey_rollback_data(self.registry_root, self.registry_key, self.registry_subkey_name, self.registry_subkey_value)
        key_creation_result = add_registry_key_and_value.set_registry_key()
        RegistryUtils.rollback_subkey(self.registry_root, self.registry_key, self.registry_subkey_name, self.registry_subkey_value, original_registry_subkey_exists, original_registry_data)
        self.assertTrue(key_creation_result)
    
    def test_rollback_value(self):
        RegistryUtils.set_data(self.registry_root, self.registry_key+"\\"+self.registry_subkey_name, "other value under subkey", "other data under subkey", True)
        add_registry_key_and_value = AddRegKeyAndValuePhaseClass(True, self.registry_root, self.registry_key, self.registry_subkey_name, self.registry_subkey_value, self.registry_subkey_data, self.cleanup)
        add_registry_key_and_value.Setup()
        add_registry_key_and_value.Run()
        add_registry_key_and_value.Cleanup()
        other_data_under_subkey = RegistryUtils.get_data(self.registry_root, self.registry_key+"\\"+self.registry_subkey_name, "other value under subkey")
        RegistryUtils.delete_key(self.registry_root, self.registry_key, self.registry_subkey_name)
        self.assertEqual(other_data_under_subkey, "other data under subkey")
    
    def test_rollback_data(self):
        RegistryUtils.set_data(self.registry_root, self.registry_key+"\\"+self.registry_subkey_name, self.registry_subkey_value, "previous data", True)
        add_registry_key_and_value = AddRegKeyAndValuePhaseClass(True, self.registry_root, self.registry_key, self.registry_subkey_name, self.registry_subkey_value, self.registry_subkey_data, self.cleanup)
        add_registry_key_and_value.Setup()
        add_registry_key_and_value.Run()
        add_registry_key_and_value.Cleanup()
        previous_data = RegistryUtils.get_data(self.registry_root, self.registry_key+"\\"+self.registry_subkey_name, self.registry_subkey_value)
        RegistryUtils.delete_key(self.registry_root, self.registry_key, self.registry_subkey_name)
        self.assertEqual(previous_data, "previous data")
