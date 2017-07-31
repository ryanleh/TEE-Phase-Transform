from ai_utils.phases.abstract_phase import AbstractPhaseClass
import logging
try:
    import _winreg
except ImportError, e:
    logging.error('error importing winreq')


class PersistenceThroughRegistryPhaseClass(AbstractPhaseClass):
    TrackerId = "200"
    Subject = "Persistence Through Registry"
    Description = "Persistence Through Registry"

    VALID_ROOT_KEYS = [
      'HKEY_CLASSES_ROOT',
      'HKEY_CURRENT_USER',
      'HKEY_LOCAL_MACHINE',
      'HKEY_USERS',
      'HKEY_CURRENT_CONFIG',
      'HKEY_PERFORMANCE_DATA'
    ]

    VALID_WINREG_ROOT_KEYS = [
      'hkcr',
      'hkcu',
      'hklm',
      'hku',
      'hkcc',
      'hkpd'
    ]

    try:
        ROOT_KEYS_OBJECTS = {
          'hkcr': _winreg.HKEY_CLASSES_ROOT,
          'hkcu': _winreg.HKEY_CURRENT_USER,
          'hklm':  _winreg.HKEY_LOCAL_MACHINE,
          'hku': _winreg.HKEY_USERS,
          'hkcc': _winreg.HKEY_CURRENT_CONFIG,
          'hkpd': _winreg.HKEY_PERFORMANCE_DATA
        }
    except:
        pass

    def __init__(self, is_phase_critical, root_key_name, key, value, data):
        AbstractPhaseClass.__init__(self, is_phase_critical)
        logging.debug('Executing Persistence Through Registry phase...')
        self.root_key = self.setup_root_key(root_key_name)
        self.full_key = "{0}\\{1}".format(self.get_full_root_key_string(root_key_name), key)
        self.key = self.setup_key(key)
        self.value = value
        self.data = data
        self.phase_successful = False

    def Setup(self):
        logging.debug('Executing Setup')
        if not self.root_key:
            self.PhaseReporter.Error('Root key parameter is invalid. Phase will fail')
            return False
        if not self.key:
            self.PhaseReporter.Error('Key parameter is invalid. Phase will fail')
            return False
        if not self.value:
            self.PhaseReporter.Error('Value parameter is invalid. Phase will fail')
            return False
        if not self.data:
            self.PhaseReporter.Error('Data parameter is invalid. Phase will fail')
            return False
        return True

    def Run(self):
        logging.debug('Executing Run')
        self.phase_successful = self.create_key()
        if self.phase_successful:
            self.PhaseReporter.Report('Registry key successfully created: {0}, With value: {1}, And data: {2}'.format(self.full_key, self.value, self.data))
            self.PhaseReporter.Mitigation('Your security controls should be configured to block the creation of the following registry key: {}'.format(self.full_key))
        else:
            self.PhaseReporter.Info('Failed to create registry key: {0}, With value: {1}, And data: {2}'.format(self.full_key, self.value, self.data))
        return self.phase_successful

    def Cleanup(self):
        logging.debug('Executing Cleanup')
        if self.phase_successful:
            if not self.delete_key():
                self.PhaseReporter.Error('Registry key could not be deleted. You might want to manually delete it: {}, Value: {}, Data: {}'.format(self.full_key, self.value, self.data))
        return True

    def get_full_root_key_string(self, abbreviated_root_key):
        try:
            root_key_list_position = self.VALID_WINREG_ROOT_KEYS.index(abbreviated_root_key)
            return self.VALID_ROOT_KEYS[root_key_list_position]
        except:
            return abbreviated_root_key

    def create_key(self):
        logging.debug('Executing create_key')
        success = False
        self.PhaseReporter.Info('Creating registry key {0}'.format(self.full_key))
        try:
            hkey = _winreg.CreateKey(self.root_key, self.key)
            _winreg.SetValueEx(hkey, self.value, 0, _winreg.REG_SZ, self.data)
            _winreg.CloseKey(hkey)
            success = True
        except Exception as e:
            self.PhaseReporter.Info('Registry key could not be created. Error: {}'.format(e))
        return success

    def delete_key(self):
        logging.debug('Executing delete_key')
        success = False
        self.PhaseReporter.Info('Removing registry key {0}'.format(self.full_key))
        try:
            hkey = _winreg.OpenKey(self.root_key, self.key, 0, _winreg.KEY_WRITE)
            _winreg.DeleteValue(hkey, self.value)
            _winreg.CloseKey(hkey)
            success = True
            self.PhaseReporter.Info('Registry key successfully deleted')
        except Exception as e:
            self.PhaseReporter.Error('Registry key could not be deleted. Error: {}'.format(e))
        return success

    def setup_root_key(self, root_key):
        logging.debug('Executing setup_root_key. root_key: {}'.format(root_key))
        for x in range(0,5):
            if root_key.upper().startswith(self.VALID_ROOT_KEYS[x]) or root_key.lower().startswith(self.VALID_WINREG_ROOT_KEYS[x]):
                return self.ROOT_KEYS_OBJECTS[self.VALID_WINREG_ROOT_KEYS[x]]
        self.PhaseReporter.Error('Root Key {0} is not valid. Valid root keys: {1} or {2}'.format(root_key, self.VALID_ROOT_KEYS, self.VALID_WINREG_ROOT_KEYS))
        return None

    def setup_key(self, key):
        logging.debug('Executing setup_key. key: {}'.format(key))
        param = ''
        if key and isinstance(key, basestring):
            param = key
            if key.startswith('\\') or key.startswith('/'):
                param = key[1:]
            param = param.lower()
        return param
