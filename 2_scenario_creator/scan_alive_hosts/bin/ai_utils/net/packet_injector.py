from ai_utils.scenarios.globals import FileUtils, PathUtils
from ai_utils.utils.registryutils import RegistryUtils
import logging
import os
try:
  # noinspection PyUnresolvedReferences
  from aipythonlib import AiPacketInjectorClass
except Exception as e:
  logging.error('AiPacketInjectorClass class from aipythonlib module could not be imported: {0}'.format(e))

class AiPacketInjector(object):
  """
  This class must be instantiated using the 'with' statement.
  """

  def __enter__(self):
    self.package_obj = InternalAiPacketInjectorClass()
    if not self.package_obj.Setup():
      logging.warning('Injector driver setup was not correct. Injecting might fail.')
    return self

  def InjectPCAP(self, pcapFilename, iface=''):
    try:
      logging.info('Injecting PCAP traffic from AiPacketInjector...')
      return self.package_obj.InternalInjectPCAP(pcapFilename, iface)
    except AttributeError:
      logging.error('You must instantiate AiPacketInjector class using the \'with\' statement.')
    return False

  def __exit__(self, type, value, traceback):
    if type is Exception:
      logging.error('A not catched exception ocurred while executing AiPacketInjector: {0}'.format(value))
    if not self.package_obj.Cleanup():
      logging.warning('Injector driver cleanup was not correct. You might want to check specific log details.')


class InternalAiPacketInjectorClass(object):
  """
  This class must not be directly called. Call AiPacketInjector class instead.
  """

  def __init__(self):
    self.IsWindowsOS = self._IsWindowsOS()
    self.DriverAlreadyInstalled = self._IsDriverAlreadyInstalled()
    self.DriverRegistryKeyAlreadyCreated = self._IsDriverRegistryKeyAlreadyCreated()
    self._LogDriverStatus()

  def Setup(self):
    logging.info(Messages.INFO12)
    return self._InstallDriverData()

  def Cleanup(self):
    logging.info(Messages.INFO11)
    return self._RemoveDriverData()

  def InternalInjectPCAP(self, pcapFilename, iface=''):
    if iface:
      logging.warning(Messages.WARN1)
    try:
      success = AiPacketInjectorClass(pcapFilename).Inject()
    except Exception as ex:
      success = False
      logging.error(Messages.ERROR1.format(ex))
    return success

  ##
  # Internal methods
  ##################

  def _IsWindowsOS(self):
    return PathUtils.GetTempDirectory() != '/tmp'

  def _IsDriverAlreadyInstalled(self):
    winPcapDriverFileName = self._GetDriverFileName()
    if FileUtils.FileExists(winPcapDriverFileName):
      logging.info(Messages.INFO4.format(winPcapDriverFileName))
      return True
    return False

  def _IsDriverRegistryKeyAlreadyCreated(self):
    root_key, key = self._GetDriverRegistryKey()
    return True if RegistryUtils.get_key_values(root_key, key) else False

  def _LogDriverStatus(self):
    logging.info(Messages.INFO13.format(self.IsWindowsOS))
    logging.info(Messages.INFO14.format(self.DriverAlreadyInstalled))
    logging.info(Messages.INFO15.format(self.DriverRegistryKeyAlreadyCreated))

  def _GetDriverPath(self):
    return r'c:\windows\system32\drivers'

  def _GetDriverFileName(self):
    return r'c:\windows\system32\drivers\npf.sys'

  def _GetDriverRegistryKey(self):
    root_key = 'hklm'
    key = r'SYSTEM\CurrentControlSet\services\NPF'
    return root_key, key

  def _InstallDriverData(self):
    success = True
    if self.IsWindowsOS:
      successDriverCopy = False
      successDriverCreateRegistryData = False
      if not self.DriverAlreadyInstalled:
        successDriverCopy = self._CopyDriverToDriversDirectory()
      else:
        logging.info(Messages.INFO9)
      if not self.DriverRegistryKeyAlreadyCreated:
        successDriverCreateRegistryData = self._CreateDriverRegistryData()
      success = successDriverCopy and successDriverCreateRegistryData
    else:
      logging.info(Messages.INFO2)
    return success

  def _CopyDriverToDriversDirectory(self):
    logging.info(Messages.INFO5)
    agentInstallDir = PathUtils.GetAgentInstallDirectory()
    if agentInstallDir:
      logging.info(Messages.INFO16.format(agentInstallDir))
      srcDirectory = os.path.join(PathUtils.GetAgentInstallDirectory(), Messages.DRIVER_NAME)
      destDirectory = self._GetDriverFileName()
      logging.info(Messages.INFO17.format(srcDirectory, destDirectory))
      return FileUtils.CopyFile(srcDirectory, destDirectory)
    else:
      logging.error(Messages.ERROR2)
    return False

  def _CreateDriverRegistryData(self):
    # TODO: Write using correct registry types. Dynamically set WOW64 value
    errorsCounter = 0
    root, key = self._GetDriverRegistryKey()
    try:
      if RegistryUtils.set_data(root, key, 'DisplayName', 'NetGroup Packet Filter Driver', create=True):
        errorsCounter += 1
      if RegistryUtils.set_data(root, key, 'ErrorControl', '1', create=True):
        errorsCounter += 1
      if RegistryUtils.set_data(root, key, 'ImagePath', 'system32\\drivers\\npf.sys', create=True):
        errorsCounter += 1
      if RegistryUtils.set_data(root, key, 'Start', '2', create=True):
        errorsCounter += 1
      if RegistryUtils.set_data(root, key, 'TimestampMode', '0', create=True):
        errorsCounter += 1
      if RegistryUtils.set_data(root, key, 'Type', '1', create=True):
        errorsCounter += 1
      if RegistryUtils.set_data(root, key, 'WOW64', '1', create=True):
        errorsCounter += 1
    except Exception as e:
      logging.error(Messages.ERROR3 + ': {0}'.format(e))
      return False
    if errorsCounter != 0:
      logging.error(Messages.ERROR3)
      return False
    return True

  def _RemoveDriver(self):
    success = False
    logging.info(Messages.INFO8)
    if not self.DriverAlreadyInstalled:
      winPcapDriverFileName = self._GetDriverFileName()
      success = FileUtils.DeleteFile(winPcapDriverFileName)
      self._LogDriverRemovalSuccess(success, winPcapDriverFileName)
    else:
      logging.info(Messages.INFO1)
    return success

  def _LogDriverRemovalSuccess(self, success, winPcapDriverFileName):
    if success:
      logging.info(Messages.INFO7.format(winPcapDriverFileName))
    else:
      logging.warning(Messages.WARN2.format(winPcapDriverFileName))

  def _RemoveDriverRegistryKey(self):
    success = False
    logging.info(Messages.INFO6)
    if not self.DriverRegistryKeyAlreadyCreated:
      rootKey, key = self._GetDriverRegistryKey()
      subkeyToRemove = key.split('\\')[-1]
      key = key.replace('\\' + subkeyToRemove, '')
      success = RegistryUtils.delete_key(rootKey, key, subkeyToRemove)
    else:
      logging.info(Messages.INFO3)
    return success

  def _RemoveDriverData(self):
    success = True
    if self.IsWindowsOS:
      successDriverRemoval = True
      successDriversRegistryKeyRemoval = True
      if not self.DriverAlreadyInstalled:
        successDriverRemoval = self._RemoveDriver()
      if not self.DriverRegistryKeyAlreadyCreated:
        successDriversRegistryKeyRemoval = self._RemoveDriverRegistryKey()
      success = successDriverRemoval and successDriversRegistryKeyRemoval
    else:
      logging.info(Messages.INFO10)
    return success



class Messages(object):

  INFO1 = 'WinPcap driver was already installed before scenario execution. It will not be removed.'
  INFO2 = 'Scenario not executed from Windows OS. WinPcap driver will not be installed.'
  INFO3 = 'WinPcap driver was already installed before scenario execution. Driver\'s registry key will not be removed.'
  INFO4 = 'WinPcap driver is already on the machine: {0}'
  INFO5 = 'Copying WinPcap driver (npf.sys) to drivers directory'
  INFO6 = 'Removing WinPcap driver\'s registry key...'
  INFO7 = 'WinPcap driver was successfully removed: {0}'
  INFO8 = 'Removing WinPcap driver from drivers directory'
  INFO9 = 'WinPcap driver was already installed before scenario execution. It will not be copied to driver\'s folder.'
  INFO10 = 'Scenario not executed from Windows OS. WinPcap driver will not be uninstalled.'
  INFO11 = 'Executing packet injector cleanup. Removing injection driver data.'
  INFO12 = 'Executing packet injector setup. Installing required driver data.'
  INFO13 = 'Is operating system Microsoft Windows: {0}'
  INFO14 = 'Is driver already in drivers directory: {0}'
  INFO15 = 'Is driver registry key already created: {0}'
  INFO16 = 'Agent Install Directory: {0}'
  INFO17 = 'Copying file: {0}, to destination: {1}'

  WARN1 = 'Interface parameter is ignored. Functionality not already implemented.'
  WARN2 = 'WinPcap driver could not be removed. You might want to manually remove it: {0}'

  ERROR1 = 'Error injecting traffic from pcap file: {0}'
  ERROR2 = 'Agent Install Directory could not be found. WinPcap driver could not be correctly installed'
  ERROR3 = 'An error ocurred creating WinPcap registry data'

  DRIVER_NAME = 'npf.sys'