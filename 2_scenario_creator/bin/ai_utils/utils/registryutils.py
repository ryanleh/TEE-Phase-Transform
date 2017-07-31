import logging
try:
    import _winreg
except ImportError as e:
    logging.error('_winreg module could not be imported. Error: {}'.format(e))


class RegistryUtils(object):
    ROOT_KEYS = ['hklm (for HKEY_LOCAL_MACHINE)',
                 'hkcr (for HKEY_CLASSES_ROOT)',
                 'hkcu (for HKEY_CURRENT_USER)',
                 'hku (for HKEY_USERS)',
                 'hkpd (for HKEY_PERFORMANCE_DATA)',
                 'hkcc (for HKEY_CURRENT_CONFIG)'
                 ]

    @staticmethod
    def get_full_name_of_short_registry_root_name(short_root_name):
        """This method retrieves the full name of a ROOT KEY given its short name.

        Args:
          short_root_name (str): The root key as abbreviated string.
                          Valid values: [hklm, hkcr, hkcu, hku, hkpd, hkcc].

        Returns:
          str. It returns full name of ROOT KEY if short name is found,
               Valid values: [HKEY_LOCAL_MACHINE, HKEY_CLASSES_ROOT ...]
              Empty string otherwise.
        """
        for rk in RegistryUtils.ROOT_KEYS:
            if short_root_name == rk.split()[0]:
                return rk.split()[-1][:-1]
        return ""

    @staticmethod
    def get_subkey_rollback_data(rootkey, key, subkey_name, subkey_value, phase_reporter=None):
        """This method gets information about a subkey to be able to perform a
        rollback later.

        Args:
          root_key (str): The root key as abbreviated string.
                          Valid values: [hklm, hkcr, hkcu, hku, hkpd, hkcc].
          key (str): The subkey starting from the root key.
                  e.g.: SYSTEM\CurrentControlSet\Services\Tcpip
          subkey_name (str): The subkey name starting from the key.
                  e.g.: Parameters
          subkey_value (str): The value to be modified under the subkey.
                  e.g.: DhcpNameServer

        Returns:
          bool. It returns True subkey exists,
              False otherwise.
          str. It returns subkey data for a given subkey and its value if they
              previously exist.
              None otherwise.
        """
        subkey = "{}\\{}".format(key, subkey_name)
        full_subkey = "{}\\{}".format(RegistryUtils.get_full_name_of_short_registry_root_name(rootkey), subkey)
        if subkey_name in RegistryUtils.get_key_values(rootkey, key):
            if phase_reporter: phase_reporter.Debug("Key {0} exists".format(full_subkey))
            original_registry_data = RegistryUtils.get_data(rootkey, subkey, subkey_value)
            if phase_reporter and original_registry_data:
                phase_reporter.Debug("Key {0} has value {1} and data {2}".format(full_subkey, subkey_value, original_registry_data))
            elif phase_reporter:
                phase_reporter.Debug("Key {0} does not has value {1}".format(full_subkey, subkey_value))
            return True, original_registry_data
        if phase_reporter: phase_reporter.Debug("Key {0} does not exists".format(full_subkey))
        return False, None

    @staticmethod
    def rollback_subkey(rootkey, key, subkey_name, subkey_value, original_subkey_exists, original_registry_data, phase_reporter=None):
        """This method rollback a subkey given its prior status.

        Args:
          root_key (str): The root key as abbreviated string.
                          Valid values: [hklm, hkcr, hkcu, hku, hkpd, hkcc].
          key (str): The subkey starting from the root key.
                  e.g.: SYSTEM\CurrentControlSet\Services\Tcpip
          subkey_name (str): The subkey name starting from the key.
                  e.g.: Parameters
          subkey_value (str): The value to be modified under the subkey.
                  e.g.: DhcpNameServer
          original_subkey_exists (bool): False if the original subkey should be deleted if
          don't previously exist, True otherwise.
          original_registry_data (str): The data with which the value will be set under the subkey.

        Returns:
          bool. It returns True subkey has been successfully rolled back,
              False otherwise.
        """
        subkey = "{}\\{}".format(key, subkey_name)
        full_subkey = "{}\\{}".format(RegistryUtils.get_full_name_of_short_registry_root_name(rootkey), subkey)
        if not original_subkey_exists:
            success = RegistryUtils.delete_key(rootkey, key, subkey_name)
            if phase_reporter and not success:
                phase_reporter.Error("Cannot delete created registry key {0}, please remove it manually.".format(full_subkey))
        elif not original_registry_data:
            success = RegistryUtils.delete_value(rootkey, subkey, subkey_value)
            if phase_reporter and not success:
                phase_reporter.Error("Cannot delete created registry value {1} on key {0}, please remove it manually.".format(full_subkey, subkey_value))
        else:
            success = RegistryUtils.set_data(rootkey, subkey, subkey_value, original_registry_data)
            if phase_reporter and not success:
                phase_reporter.Error("Cannot rollback registry key {0} with value {1} and data {2}, please set it manually.".format(full_subkey, subkey_value, original_registry_data))
        if phase_reporter and success:
            phase_reporter.Info("Registry key rolled back successfully")
        return success


    @staticmethod
    def set_data(rootkey, key, value, data, create=False):
        """This method acts as a wrapper for the internal __set_data method.

        Args:
          root_key (str): The root key as abbreviated string.
                          Valid values: [hklm, hkcr, hkcu, hku, hkpd, hkcc].
          key (str): The subkey starting from the root key.
                  e.g.: SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
          value (str): The value to be modified under the key.
                  e.g.: DhcpNameServer
          data (str): The data with which the value will be set under the key.
          create (bool): True if the  key and value should be created if
          don't previously exist, False otherwise.

        Returns:
          bool. It returns True if the value has been correctly modified,
              False otherwise.
        """
        rks = [rk.split()[0] for rk in RegistryUtils.ROOT_KEYS]
        if rootkey == rks[0]:
            return RegistryUtils.__set_data(_winreg.HKEY_LOCAL_MACHINE, key, value, data, create)
        elif rootkey == rks[1]:
            return RegistryUtils.__set_data(_winreg.HKEY_CLASSES_ROOT, key, value, data, create)
        elif rootkey == rks[2]:
            return RegistryUtils.__set_data(_winreg.HKEY_CURRENT_USER, key, value, data, create)
        elif rootkey == rks[3]:
            return RegistryUtils.__set_data(_winreg.HKEY_USERS, key, value, data, create)
        elif rootkey == rks[4]:
            return RegistryUtils.__set_data(_winreg.HKEY_PERFORMANCE_DATA, key, value, data, create)
        elif rootkey == rks[5]:
            return RegistryUtils.__set_data(_winreg.HKEY_CURRENT_CONFIG, key, value, data, create)
        else:
            logging.error('Incorrect registry root key value: {0}. Valid values: {1}'.format(rootkey, RegistryUtils.ROOT_KEYS))
        return False

    @staticmethod
    def get_data(rootkey, key, value):
        """This method acts as a wrapper for the internal __get_data method.

        Args:
          root_key (str): The root key as abbreviated string.
                          Valid values: [hklm, hkcr, hkcu, hku, hkpd, hkcc].
          key (str): The subkey starting from the root key.
                  e.g.: SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
          value (str): The value to query.
                  e.g.: DhcpNameServer

        Returns:
          str. It returns the retrieved data if the value is correct,
              or an empty string otherwise.
        """
        rks = [rk.split()[0] for rk in RegistryUtils.ROOT_KEYS]
        if rootkey == rks[0]:
            return RegistryUtils.__get_data(_winreg.HKEY_LOCAL_MACHINE, key, value)
        elif rootkey == rks[1]:
            return RegistryUtils.__get_data(_winreg.HKEY_CLASSES_ROOT, key, value)
        elif rootkey == rks[2]:
            return RegistryUtils.__get_data(_winreg.HKEY_CURRENT_USER, key, value)
        elif rootkey == rks[3]:
            return RegistryUtils.__get_data(_winreg.HKEY_USERS, key, value)
        elif rootkey == rks[4]:
            return RegistryUtils.__get_data(_winreg.HKEY_PERFORMANCE_DATA, key, value)
        elif rootkey == rks[5]:
            return RegistryUtils.__get_data(_winreg.HKEY_CURRENT_CONFIG, key, value)
        else:
            logging.error('Incorrect registry root key value: {0}. Valid values: {1}'.format(rootkey, RegistryUtils.ROOT_KEYS))
        return ''

    @staticmethod
    def get_key_values(rootkey, key):
        """This method acts as a wrapper for the internal __get_key_values method.

        Args:
          root_key (str): The root key as abbreviated string.
                          Valid values: [hklm, hkcr, hkcu, hku, hkpd, hkcc].
          key (str): The subkey starting from the root key.
                  e.g.: SYSTEM\CurrentControlSet\Services\Tcpip\Parameters

        Returns:
          list. It returns the retrieved values and subkeys
          or an empty list if data could not be retrieved.
        """
        rks = [rk.split()[0] for rk in RegistryUtils.ROOT_KEYS]
        if rootkey == rks[0]:
            return RegistryUtils.__get_key_values(_winreg.HKEY_LOCAL_MACHINE, key)
        elif rootkey == rks[1]:
            return RegistryUtils.__get_key_values(_winreg.HKEY_CLASSES_ROOT, key)
        elif rootkey == rks[2]:
            return RegistryUtils.__get_key_values(_winreg.HKEY_CURRENT_USER, key)
        elif rootkey == rks[3]:
            return RegistryUtils.__get_key_values(_winreg.HKEY_USERS, key)
        elif rootkey == rks[4]:
            return RegistryUtils.__get_key_values(_winreg.HKEY_PERFORMANCE_DATA, key)
        elif rootkey == rks[5]:
            return RegistryUtils.__get_key_values(_winreg.HKEY_CURRENT_CONFIG, key)
        else:
            logging.error('Incorrect registry root key value: {0}. Valid values: {1}'.format(rootkey, RegistryUtils.ROOT_KEYS))
        return []

    @staticmethod
    def delete_key(rootkey, key, subkey):
        """This method acts as a wrapper for the internal __delete_key method.

        Args:
          root_key (str): The root key as abbreviated string.
                          Valid values: [hklm, hkcr, hkcu, hku, hkpd, hkcc].
          key (str): The subkey starting from the root key.
                  e.g.: SYSTEM\CurrentControlSet\Services
          subkey (str): The subkey to delete.
                  e.g.: NPF

        Returns:
          bool. It returns True if the key has been correctly deleted,
              False otherwise.
        """
        rks = [rk.split()[0] for rk in RegistryUtils.ROOT_KEYS]
        if rootkey == rks[0]:
            return RegistryUtils.__delete_key(_winreg.HKEY_LOCAL_MACHINE, key, subkey)
        elif rootkey == rks[1]:
            return RegistryUtils.__delete_key(_winreg.HKEY_CLASSES_ROOT, key, subkey)
        elif rootkey == rks[2]:
            return RegistryUtils.__delete_key(_winreg.HKEY_CURRENT_USER, key, subkey)
        elif rootkey == rks[3]:
            return RegistryUtils.__delete_key(_winreg.HKEY_USERS, key, subkey)
        elif rootkey == rks[4]:
            return RegistryUtils.__delete_key(_winreg.HKEY_PERFORMANCE_DATA, key, subkey)
        elif rootkey == rks[5]:
            return RegistryUtils.__delete_key(_winreg.HKEY_CURRENT_CONFIG, key, subkey)
        else:
            logging.error('Incorrect registry root key value: {0}. Valid values: {1}'.format(rootkey, RegistryUtils.ROOT_KEYS))
        return False

    @staticmethod
    def delete_value(rootkey, key, value):
        """This method acts as a wrapper for the internal __delete_key method.

        Args:
          root_key (str): The root key as abbreviated string.
                          Valid values: [hklm, hkcr, hkcu, hku, hkpd, hkcc].
          key (str): The subkey starting from the root key.
                  e.g.: SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
          value (str): The value to delete.
                  e.g.: DhcpNameServer

        Returns:
          bool. It returns True if the value has been correctly modified,
              False otherwise.
        """
        rks = [rk.split()[0] for rk in RegistryUtils.ROOT_KEYS]
        if rootkey == rks[0]:
            return RegistryUtils.__delete_value(_winreg.HKEY_LOCAL_MACHINE, key, value)
        elif rootkey == rks[1]:
            return RegistryUtils.__delete_value(_winreg.HKEY_CLASSES_ROOT, key, value)
        elif rootkey == rks[2]:
            return RegistryUtils.__delete_value(_winreg.HKEY_CURRENT_USER, key, value)
        elif rootkey == rks[3]:
            return RegistryUtils.__delete_value(_winreg.HKEY_USERS, key, value)
        elif rootkey == rks[4]:
            return RegistryUtils.__delete_value(_winreg.HKEY_PERFORMANCE_DATA, key, value)
        elif rootkey == rks[5]:
            return RegistryUtils.__delete_value(_winreg.HKEY_CURRENT_CONFIG, key, value)
        else:
            logging.error('Incorrect registry root key value: {0}. Valid values: {1}'.format(rootkey, RegistryUtils.ROOT_KEYS))
        return []

    @staticmethod
    def __set_data(root_key, key, value, data, create=False):
        """This method sets the data from the given key and value under the given
        root key.

        Args:
          root_key (_winreg HKEY_* Constants): To set this value use set_data method.
          key (str): The subkey starting from the root key.
                  e.g.: SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
          value (str): The value to be modified under the key.
          data (str): The data with which the value will be set under the key.
          create (bool): True if the  key and value should be created if
          don't previously exist, False otherwise.

        Returns:
          bool. It returns True if the value has been correctly modified,
              False otherwise.
        """
        success = False
        try:
            if create:
                _winreg.CreateKey(root_key, key)
            hkey = _winreg.OpenKey(root_key, key, 0, _winreg.KEY_WRITE)
            _winreg.SetValueEx(hkey, value, 0, _winreg.REG_SZ, data)
            _winreg.CloseKey(hkey)
            success = True
        except WindowsError as e:
            logging.error('Error occurred setting registry data: {0}'.format(e))
        return success

    @staticmethod
    def __get_data(root_key, key, value):
        """This method gets the data from the given key and value under the root
        key.

        Args:
          root_key (str): The root key as abbreviated string.
                          Valid values: [hklm, hkcr, hkcu, hku, hkpd, hkcc].
          key (str): The subkey starting from the root key.
                  e.g.: SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
          value (str): The value to query.

        Returns:
          Str. It returns the retrieved data, or an empty string if data could not be retrieved.
        """
        data = ''
        try:
            hkey = _winreg.OpenKey(root_key, key, 0, _winreg.KEY_READ)
            data, regtype = _winreg.QueryValueEx(hkey, value)
            _winreg.CloseKey(hkey)
        except WindowsError as e:
            logging.error('Error occurred getting registry data: {0}'.format(e))
        return data

    @staticmethod
    def __get_key_values(root_key, key):
        """This method gets the values and subkeys from the given key under the
        root key.

        Args:
          root_key (str): The root key as abbreviated string.
                          Valid values: [hklm, hkcr, hkcu, hku, hkpd, hkcc].
          key (str): The subkey starting from the root key.
                  e.g.: SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\interfaces
        Returns:
          list. It returns the retrieved values and subkeys
          or an empty list if data could not be retrieved.
        """
        values = []
        i = 0
        try:
            hkey = _winreg.OpenKey(root_key, key, 0, _winreg.KEY_READ)
        except WindowsError as e:
            logging.error('Key ({0}) could not be opened: {1}'.format(key, e))
            return values

        while True:
            try:
                value = _winreg.EnumKey(hkey, i)
                values.append(value)
                i += 1
            except WindowsError:
                logging.info('No more values. Total values: {0}'.format(i))
                if hkey:
                    _winreg.CloseKey(hkey)
                break  # no more values
        return values

    @staticmethod
    def __delete_key(root_key, key, subkey):
        """This method deletes a registry key. The key can not have subkeys.

        Args:
          root_key (_winreg HKEY_* Constants): To set this value use delete_key method.
          key (str): The subkey starting from the root key.
                  e.g.: SYSTEM\CurrentControlSet\Services
          subkey (str): The subkey starting from the key to delete.
                  e.g.: NPF

        Returns:
          bool. It returns True if the key has been correctly deleted,
              False otherwise.
        """
        success = False
        try:
            hkey = _winreg.OpenKey(root_key, key, 0, _winreg.KEY_WRITE)
            _winreg.DeleteKey(hkey, subkey)
            _winreg.CloseKey(hkey)
            success = True
        except WindowsError as e:
            logging.error('Error occurred deleting registry key: {0}'.format(e))
        return success

    @staticmethod
    def __delete_value(root_key, key, value):
        """This method deletes a registry value.

        Args:
          root_key (_winreg HKEY_* Constants): To set this value use delete_value method.
          key (str): The subkey starting from the root key.
                  e.g.: Environment
          value (str): The value to delete.

        Returns:
          bool. It returns True if the value has been correctly deleted,
              False otherwise.
        """
        success = False
        try:
            hkey = _winreg.OpenKey(root_key, key, 0, _winreg.KEY_WRITE)
            _winreg.DeleteValue(hkey, value)
            _winreg.CloseKey(hkey)
            success = True
        except WindowsError as e:
            logging.error('Error occurred deleting registry value: {0}'.format(e))
        return success
