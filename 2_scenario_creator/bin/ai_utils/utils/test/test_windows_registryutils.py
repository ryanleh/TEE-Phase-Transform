import unittest
from ai_utils.utils.registryutils import RegistryUtils
import logging


class TestRegistryUtilsClass(unittest.TestCase):

    def test_regops_get_data(self):
        rootKey = 'hklm'
        key = r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
        value = 'DataBasePath'
        expected = '%SystemRoot%\System32\drivers\etc'

        data = RegistryUtils.get_data(rootKey, key, value)

        self.assertEqual(data, expected, 'Error: retrieved data: {0}, expected: {1}'.format(data, expected))

    def test_regops_get_keys(self):
        rootKey = 'hklm'
        key = r'SYSTEM\CurrentControlSet\Services\Tcpip'
        expected = ['Linkage', 'Parameters', 'Performance', 'Security', 'ServiceProvider']

        data = RegistryUtils.get_key_values(rootKey, key)

        self.assertEqual(data, expected, 'Error: retrieved keys: {0}, expected: {1}'.format(data, expected))

    def test_regops_set_existing_value(self):
        rootKey = 'hklm'
        key = r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
        value = 'DataBasePath'
        expected = 'ThisIsATest'

        previousData = self._getPreviousData(rootKey, key, value)
        modifiedData = self._setAndCheckData(rootKey, key, value, expected)
        self._restoreData(rootKey, key, value, previousData)

        self.assertEqual(modifiedData, expected, 'Error: retrieved data: {0}, expected: {1}'.format(modifiedData, expected))

    def test_regops_set_not_existing_value(self):
        rootKey = 'hklm'
        key = r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
        value = 'NonExistingValue'
        expected = 'ThisIsATest'

        createdData = self._setAndCheckData(rootKey, key, value, expected, create=True)
        self._deleteValue(rootKey, key, value)

        self.assertEqual(createdData, expected, 'Error: retrieved data: {0}, expected: {1}'.format(createdData, expected))

    def test_delete_key(self):
        rootKey = 'hkcu'
        keyToCreate = r'ai-depth1-key\depth2'
        key = 'ai-depth1-key'
        subkeyToRemove = 'depth2'
        value = 'NonExistingValue'
        data = 'ThisIsATest'

        self._setAndCheckData(rootKey, keyToCreate, value, data, create=True)
        success = RegistryUtils.delete_key(rootKey, key, subkeyToRemove)
        self.assertTrue(success, 'Error: Key {0}, {1}, {2} could not be deleted.'.format(rootKey, key, subkeyToRemove))

    def test_delete_key_one_level(self):
        rootKey = 'hkcu'
        keyToCreate = 'ai-depth1-key'
        subkeyToRemove = 'ai-depth1-key'
        value = 'NonExistingValue'
        data = 'ThisIsATest'

        self._setAndCheckData(rootKey, keyToCreate, value, data, create=True)
        success = RegistryUtils.delete_key(rootKey, '', subkeyToRemove)
        self.assertTrue(success, 'Error: Key {0}, {1}, {2} could not be deleted.'.format(rootKey, keyToCreate, subkeyToRemove))

    def test_delete_value(self):
        rootKey = 'hkcu'
        key = r'Environment'
        value = 'NonExistingValue'
        expected = 'ThisIsATest'

        self._setAndCheckData(rootKey, key, value, expected, create=True)
        success = RegistryUtils.delete_value(rootKey, key, value)
        self.assertTrue(success, 'Error: Key {0}, {1} could not be deleted.'.format(rootKey, key))

    def test_get_full_name_of_short_registry_root_name(self):
        root_keys = {'hklm': 'HKEY_LOCAL_MACHINE',
                     'hkcr': 'HKEY_CLASSES_ROOT',
                     'hkcu': 'HKEY_CURRENT_USER',
                     'hku': 'HKEY_USERS',
                     'hkpd': 'HKEY_PERFORMANCE_DATA',
                     'hkcc': 'HKEY_CURRENT_CONFIG'}
        for short_name, expected_full_name in root_keys.iteritems():
            full_name = RegistryUtils.get_full_name_of_short_registry_root_name(short_name)
            self.assertTrue(full_name==expected_full_name, 'Error: received full name {} does not match with expected full name {} for short name {}'.format(full_name, expected_full_name, short_name))

    def test_rollback_functionality_non_existant_key(self):
        rootKey = 'hkcu'
        key = r'Environment'
        subkey = 'NonExistingSubkey'
        key_subkey = key+"\\"+subkey
        value = 'NonExistingValue'
        data = 'NonExistingData'

        original_registry_subkey_exists, original_registry_data = RegistryUtils.get_subkey_rollback_data(rootKey, key, subkey, value)
        self.assertFalse(original_registry_subkey_exists, 'Error: Key {} exists but it should not'.format(key_subkey))
        RegistryUtils.set_data(rootKey, key_subkey, value, data, True)
        RegistryUtils.rollback_subkey(rootKey, key, subkey, value, original_registry_subkey_exists, original_registry_data)
        subkeys_after_rollback = RegistryUtils.get_key_values(rootKey, key)
        RegistryUtils.delete_key(rootKey, key, subkey)
        self.assertFalse(subkey in subkeys_after_rollback, 'Error: Rollback failed (subkey {} should not be present on key {}'.format(subkey, key))

    def test_rollback_functionality_existant_key_and_data(self):
        rootKey = 'hkcu'
        key = r'Environment'
        subkey = 'NonExistingSubkey'
        key_subkey = key+"\\"+subkey
        value = 'NonExistingValue'
        data = 'NonExistingData'

        RegistryUtils.set_data(rootKey, key_subkey, value, data, True)
        original_registry_subkey_exists, original_registry_data = RegistryUtils.get_subkey_rollback_data(rootKey, key, subkey, value)
        if not original_registry_subkey_exists:
            RegistryUtils.delete_key(rootKey, key, subkey)
            raise AssertionError('Error: Seems that key {} does not exists'.format(key_subkey))
        if not data==original_registry_data:
            RegistryUtils.delete_key(rootKey, key, subkey)
            raise AssertionError('Error: current registry data {} does not match with expected data {}'.format(original_registry_data, data))
        RegistryUtils.set_data(rootKey, key_subkey, value, "new_data")
        RegistryUtils.rollback_subkey(rootKey, key, subkey, value, original_registry_subkey_exists, original_registry_data)
        restored_data = RegistryUtils.get_data(rootKey, key_subkey, value)
        RegistryUtils.delete_key(rootKey, key, subkey)
        self.assertTrue(data == restored_data, 'Error: Rollback failed (current data is {}, {} was expected'.format(restored_data, data))

    def _getPreviousData(self, rootKey, key, value):
        previousData = RegistryUtils.get_data(rootKey, key, value)
        if not previousData:
            raise AssertionError('Data for key {0}, {1}, {2} could not be retrieved. '
                                 'Test is not further executed because data will not be correctly restored.'
                                 .format(rootKey, key, value))
        return previousData

    def _setAndCheckData(self, rootKey, key, value, data, create=False):
        success = RegistryUtils.set_data(rootKey, key, value, data, create)
        if not success:
            raise AssertionError('Data could not be set. Stopping test.')
        modifiedData = RegistryUtils.get_data(rootKey, key, value)
        if not modifiedData:
            raise AssertionError('Modified data could not be checked. Stopping test.')
        return modifiedData

    def _restoreData(self, rootKey, key, value, data):
        success = True
        if not RegistryUtils.set_data(rootKey, key, value, data):
            logging.error('Data could not be restored for registry: {0}, {1}, {2} with data: {3}'.format(rootKey, key, value, data))
            logging.error('You should set it to default value. Usually: {0}'.format('%SystemRoot%\System32\drivers\etc'))
            return False
        return success

    def _deleteValue(self, rootKey, key, value):
        success = RegistryUtils.delete_value(rootKey, key, value)
        if not success:
            logging.error('Value {0}, {1}, {2} could not be deleted. You might want to manually delete it.'.format(rootKey, key, value))
        return success
