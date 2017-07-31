import logging
from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.utils.registryutils import RegistryUtils


class AddRegKeyAndValuePhaseClass(AbstractPhaseClass):
    TrackerId = "6e8779b6-a05e-43eb-9c93-c754d489f198"
    Subject = "Set Registry Values"
    Description = "This Phase checks for a registry value, creates a key, and sets a pair of value and data for that new key"

    def __init__(self, is_phase_critical, registry_root, registry_key, registry_subkey_name, registry_subkey_value, registry_subkey_data, rollback):
        """
          This Phase checks for a registry value, creates a key, and sets a pair of value and data for that new key.
          If the registry key to be modified is already created, it is possible to do a backup before modifying it, and a rollback after phase has finished its tests.

          :param is_phase_critical (bool): Dictates if the phase is critical.
          :param registry_root(str): Registry root to use, valid values are "hklm", "hkcr", "hkcu", "hku", "hkpd" and "hkcc" (obtained form RegistryUtils.ROOT_KEYS).
          :param registry_key(str): Specifies the registry path of the key.
          :param registry_subkey_name: Key name which will be created under registry_key
          :param registry_subkey_value(str): Specifies the value to be created on registry_key\registry_subkey_name.
          :param registry_subkey_data(str): Specifies the data to be set to the created value.
          :param rollback(bool): Specifies if the scenario has to undo the registry modifications.

          :return: True if the given registry key can be created and set as desired, False otherwise
          """
        logging.debug('Executing __init__. is_phase_critical: {}, registry_root: {} registry_key: {} registry_subkey_name:{} registry_subkey_value:{} registry_subkey_data:{} rollback:{}'.format(is_phase_critical, registry_root, registry_key, registry_subkey_name, registry_subkey_value, registry_subkey_data, rollback))
        AbstractPhaseClass.__init__(self, is_phase_critical)
        self.registry_root = registry_root
        self.registry_root_full_name = ""
        self.registry_key = registry_key
        self.registry_subkey_name = registry_subkey_name
        self.registry_subkey_value = registry_subkey_value
        self.registry_subkey_data = registry_subkey_data
        self.rollback = rollback
        self.registry_subkey = ""
        self.original_registry_subkey_exists = False
        self.original_registry_data = ""
        self.created_subkey_and_value = False

    def Setup(self):
        logging.debug('Executing Setup')
        if not self.registry_root:
            self.PhaseReporter.Error('Registry root parameter was not specified. Unknown registry key to be accessed')
            return False
        self.registry_root_full_name = RegistryUtils.get_full_name_of_short_registry_root_name(self.registry_root)
        if not self.registry_root_full_name:
            self.PhaseReporter.Error('Registry root is not correct, it should have one of the following values: "hklm", "hkcr", "hkcu", "hku", "hkpd" or "hkcc". Unknown registry key to be accessed')
            return False
        if not self.registry_key:
            self.PhaseReporter.Error('Registry key parameter was not specified. Unknown registry key to be accessed')
            return False
        if not self.registry_subkey_name:
            self.PhaseReporter.Error('Registry subkey name parameter was not specified. Unknown registry subkey to be created')
            return False
        if not self.registry_subkey_data:
            self.PhaseReporter.Error('Registry_subkey_data was not specified. Unknown registry data to be set')
            return False
        if not isinstance(self.rollback, bool):
            self.PhaseReporter.Error('rollback was not specified or it is not a boolean. Rollback will fail')
            return False
        self.registry_subkey = self.registry_key + "\\" + self.registry_subkey_name
        return True

    def Run(self):
        logging.debug('Executing Run')
        self.original_registry_subkey_exists, self.original_registry_data = RegistryUtils.get_subkey_rollback_data(self.registry_root, self.registry_key, self.registry_subkey_name, self.registry_subkey_value, self.PhaseReporter)
        phase_successful  = self.set_registry_key()
        self.log_success(phase_successful)
        return phase_successful

    def Cleanup(self):
        logging.debug('Executing Cleanup')
        if self.rollback and self.created_subkey_and_value:
            RegistryUtils.rollback_subkey(self.registry_root, self.registry_key, self.registry_subkey_name, self.registry_subkey_value, self.original_registry_subkey_exists, self.original_registry_data, self.PhaseReporter)

    def set_registry_key(self):
        logging.debug('Executing set_registry_key')
        result = False
        if RegistryUtils.set_data(self.registry_root, self.registry_subkey, self.registry_subkey_value, self.registry_subkey_data, create=True):
            if self.registry_subkey_value:
                self.PhaseReporter.Debug("Key {0}\{1}\{2} was created with data {3}".format(self.registry_root_full_name, self.registry_subkey, self.registry_subkey_value, self.registry_subkey_data))
            else:
                self.PhaseReporter.Debug("Default value for key {0}\{1} was created with data {2}".format(self.registry_root_full_name, self.registry_subkey, self.registry_subkey_data))
            self.created_subkey_and_value = True
            result = True
        else:
            self.PhaseReporter.Warn("Cannot create and set key {0}\{1}\{2} with value {3}".format(self.registry_root_full_name, self.registry_subkey, self.registry_subkey_value, self.registry_subkey_data))
        return result

    def log_success(self, phase_successful):
        logging.debug('Executing log_success. phase_successful:{}'.format(phase_successful))
        if phase_successful:
            self.PhaseReporter.Info("Registry key created and value set successfully")
            if self.registry_subkey_value:
                self.PhaseReporter.Report("It was possible to create and modify the registry subkey {0}\{1} with value {2} and data {3}".format(self.registry_root_full_name, self.registry_subkey, self.registry_subkey_value , self.registry_subkey_data))
            else:
                self.PhaseReporter.Report("It was possible to create and modify the default value of registry subkey {0}\{1} with data {2}".format(self.registry_root_full_name, self.registry_subkey , self.registry_subkey_data))
            self.PhaseReporter.Mitigation('Forbid registry changes to the following key: {0}\{1}'.format(self.registry_root_full_name, self.registry_subkey))
        else:
            self.PhaseReporter.Info("It was not possible to create the registry key")
