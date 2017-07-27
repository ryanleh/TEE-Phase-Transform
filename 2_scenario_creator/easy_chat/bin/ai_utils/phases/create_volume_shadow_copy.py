from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.utils.offensive.powershell import PowershellUtilsClass
from ai_utils.utils.scenarioutils import PathUtils
from ai_utils.utils.filecollector import FileCollectorClass
import logging


class CreateVolumeShadowCopyPhaseClass(AbstractPhaseClass):
  TrackerId = "PHS-15c60efb-f1f1-11e5-b088-d8cb8a2a09d1"
  Subject = "Copy Data using Volume Shadow Copy Service"
  Description = "This phase make a backup of data using the Volume Shadow Copy Service"

  def __init__(self, is_phase_critical, automatic_cleanup=True):
    AbstractPhaseClass.__init__(self, is_phase_critical)
    logging.debug('Executing CreateVolumeShadowCopyPhaseClass constructor. is_phase_critical: {}, automatic_cleanup: {}'.format(is_phase_critical, automatic_cleanup))
    self.remove_volume_shadow_copy = False
    self.automatic_cleanup = self.setup_automatic_cleanup_parameter(automatic_cleanup)
    self.shadow_id = None
    self.shadow_path = None

  def Setup(self):
    if not self.is_powershell_installed():
      self.PhaseReporter.Error('PowerShell could not be found in the asset\'s system. Phase requires PowerShell')
      return False
    return True

  def Run(self):
    logging.debug('Executing Run')
    phase_successful = False
    if self.volume_shadow_copy_creation():
      if self.get_volume_shadow_copy_path():
        phase_successful = True
        self.remove_volume_shadow_copy = True
    return phase_successful

  def Cleanup(self):
    logging.debug('Executing Cleanup')
    success = True
    if self.automatic_cleanup and self.remove_volume_shadow_copy and self.shadow_id:
      success = self.delete_volume_shadow_copy()
    return success

  def manual_cleanup(self):
    logging.debug('Executing manual_cleanup')
    success = True
    if self.shadow_id:
      success = self.delete_volume_shadow_copy()
    return success

  def volume_shadow_copy_creation(self):
    logging.debug('Executing volume_shadow_copy_creation')
    success = self.create_volume_shadow_copy()
    self.remove_volume_shadow_copy = success
    return success

  def create_volume_shadow_copy(self):
    logging.debug('Executing create_volume_shadow_copy')
    cmd = r'(Get-WMIObject Win32_ShadowCopy -List).Create(\"C:\\\", \"ClientAccessible\").ShadowID'
    self.PhaseReporter.Debug('Executing PowerShell command: {}'.format(cmd))
    self.shadow_id, exit_code = PowershellUtilsClass.ExecutePowerShellCommand(cmd, timeout=90000)
    logging.info('Shadow ID: "{}", Exit Code: "{}", after executing PowerShell command: "{}"'.format(self.shadow_id, exit_code, cmd))
    success = exit_code == 0
    self.log_creation_success(success)
    return success

  def delete_volume_shadow_copy(self):
    logging.debug('Executing delete_volume_shadow_copy')
    cmd = r'(Get-WMIObject Win32_ShadowCopy | where {{$_.ID -eq \"{0}\"}} ).Delete()'.format(self.shadow_id)
    self.PhaseReporter.Debug('Executing PowerShell command: {}'.format(cmd))
    _, exit_code = PowershellUtilsClass.ExecutePowerShellCommand(cmd, timeout=50000)
    logging.info('Exit Code: "{}", after executing PowerShell command: "{}"'.format(self.shadow_id, exit_code, cmd))
    success = exit_code == 0
    self.log_deletion_success(success)
    return success

  def get_volume_shadow_copy_path(self):
    logging.debug('Executing get_volume_shadow_copy_path')
    cmd = r"(Get-WMIObject Win32_ShadowCopy | where {{$_.ID -eq \"{0}\"}}).DeviceObject".format(self.shadow_id)
    self.PhaseReporter.Debug('Executing PowerShell command: {}'.format(cmd))
    self.shadow_path, exit_code = PowershellUtilsClass.ExecutePowerShellCommand(cmd, format=None, timeout=50000)
    logging.info('Shadow Path: "{}", Exit Code: "{}", after executing PowerShell command: "{}"'.format(self.shadow_path, exit_code, cmd))
    self.PhaseReporter.Debug('Volume Shadow Copy path: {}'.format(self.shadow_path))
    success = exit_code == 0
    self.log_path_success(success)
    return success

  def log_creation_success(self, success):
    logging.debug('Executing log_creation_success')
    if success:
      self.PhaseReporter.Info('Volume Shadow Copy with ID "{}" successfully created using PowerShell'.format(self.shadow_id))
    else:
      self.PhaseReporter.Info('Volume Shadow Copy could not be created. PowerShell script execution may have been prevented.')

  def log_deletion_success(self, success):
    logging.debug('Executing log_deletion_success. success: {}'.format(success))
    if success:
      self.PhaseReporter.Info('Volume Shadow Copy with ID "{}" successfully deleted using PowerShell'.format(self.shadow_id))
    else:
      self.PhaseReporter.Info('Volume Shadow Copy with ID {}, could not be deleted'.format(self.shadow_id))

  def log_path_success(self, success):
    logging.debug('Executing log_path_success. success: {}'.format(success))
    if success:
      self.PhaseReporter.Debug('Path for Volume Shadow Copy with ID: "{}" is: "{}"'.format(self.shadow_id, self.shadow_path))
    else:
      self.PhaseReporter.Debug('Path for Volume Shadow Copy with ID: {} could not be retrieved'.format(self.shadow_id))

  def setup_automatic_cleanup_parameter(self, automatic_cleanup):
    logging.debug('Executing setup_automatic_cleanup_parameter. automatic_cleanup: {}'.format(automatic_cleanup))
    if not isinstance(automatic_cleanup, bool):
      self.PhaseReporter.Debug('Automatic Cleanup parameter was not boolean. It has been set to True, so cleanup happens by default')
      param = True
    else:
      param = automatic_cleanup
    self.PhaseReporter.Debug('Automatic Cleanup parameter: {}'.format(param))
    return param

  def is_powershell_installed(self):
    logging.debug('Executing is_powershell_installed')
    is_installed = False
    PathUtils.AddToSearchPath(r'C:\WINDOWS\system32\WindowsPowerShell')
    fc = FileCollectorClass([r'C:\WINDOWS\system32\WindowsPowerShell'], ['powershell.exe'], maximumCount=1)
    if fc.Collect():
      is_installed = True
    return is_installed
