from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.scenarios.globals import FileUtils, PathUtils
import logging
import os
from tempfile import NamedTemporaryFile

try:
  import aipythonlib
except Exception as e:
  logging.info("Failed to import aipythonlib. Phase will fail.")


class ExecutePowerShellScriptPhaseClass(AbstractPhaseClass):
  TrackerId = "841"
  Subject = "PowerShell Scripting"
  Description = "This phase executes a Powershell script and tests if it is successful."

  def __init__(self, isPhaseCritical, shellInput, runAsLoggedInUser, path):
    AbstractPhaseClass.__init__(self, isPhaseCritical)
    logging.info(Messages.INFO1)
    self.RunAsLoggedInUser = self._SetupRunAsLoggedInUserParameter(runAsLoggedInUser)
    self.ShellInput = self._SetupShellInputParameter(shellInput)
    self.FilePath = self._SetupFilePathParameter(path)
    self.ShellScriptName = ''

  def Setup(self):
    if not self.ShellInput:
      self.PhaseReporter.Error(Messages.ERROR1)
      return False
    elif not self.FilePath:
      self.PhaseReporter.Error(Messages.ERROR2)
      return False
    return True

  def Run(self):
    phaseSuccessful = False
    if self._CreateShellScript():
      phaseSuccessful = self._ExecuteShellScript()
    self._LogSuccess(phaseSuccessful)
    return phaseSuccessful

  def RemoveShellScript(self):
    success = True
    if not FileUtils.DeleteFile(self.ShellScriptName):
      success = False
      self.PhaseReporter.Warn(Messages.WARN1.format(self.ShellScriptName))
    return success

  def Cleanup(self):
    logging.info(Messages.INFO5)
    return self.RemoveShellScript()

  ###
  # Internal methods
  #################

  def _WriteScriptToFile(self, shellScript):
    if FileUtils.WriteToFile(shellScript, self.ShellInput):
      self.ShellScriptName = shellScript
      logging.info(Messages.INFO2.format(shellScript))
      success = True
    else:
      self.PhaseReporter.Error(Messages.ERROR6)
      success = False
    return success

  def _CreateShellScript(self):
    logging.info(Messages.INFO1)
    shellScript = self._GetTempFile(prefixArg='ai-ps', suffixArg='.ps1', dirPath=self.FilePath)
    success = self._WriteScriptToFile(shellScript)
    if not success:
      self.PhaseReporter.Error(Messages.ERROR8)
    return success

  def _ExecuteShellScript(self):
    self.PhaseReporter.Info(Messages.INFO3)
    shellCommand = '-InputFormat None "{0}" '.format(self.ShellScriptName)
    logging.info(Messages.INFO4.format(shellCommand))
    success = self._RunScriptCommand(shellCommand)
    return success

  def _RunScriptCommand(self, shellCommand):
    timeout = 5000
    success = False
    try:
      if not self.RunAsLoggedInUser:
        errorCode, exitCode, stdOut, stdErr = aipythonlib.AiRunCommand('powershell', shellCommand, timeout)
      else:
        errorCode, exitCode, stdOut, stdErr = aipythonlib.AiRunCommandAsActiveLoggedInUser('powershell', shellCommand, timeout)
      logging.info(Messages.INFO9.format(stdOut))
      logging.info(Messages.ERROR7.format(stdErr))
      success = self._CheckIfSuccessful(exitCode, errorCode)
      if not success:
        self._LogCommandExecutionSuccess(stdErr, exitCode, errorCode)
    except Exception:
      logging.info(Messages.ERROR5.format())
    return success

  def _LogCommandExecutionSuccess(self, stdErr, exitCode, errorCode):
    self.PhaseReporter.Error(Messages.ERROR5.format(stdErr))
    self.PhaseReporter.Error(Messages.ERROR10.format(exitCode))
    self.PhaseReporter.Error(Messages.ERROR11.format(errorCode))

  def _CheckIfSuccessful(self, exitCode, errorCode):
    if exitCode == 0 and errorCode == 0:
      return True
    return False

  def _SetupFilePathParameter(self, filePath):
    if filePath:
      filePath = os.path.expandvars(filePath)
      param = self._VerifyAndAssignPath(filePath)
    else:
      param = PathUtils.GetTempDirectory()
      self.PhaseReporter.Info(Messages.INFO11.format(param))
    return param

  def _VerifyAndAssignPath(self, filePath):
    if os.path.exists(filePath) or os.access(os.path.dirname(filePath), os.W_OK):
      param = filePath
      self.PhaseReporter.Info(Messages.INFO11.format(param))
    else:
      param = False
      self.PhaseReporter.Error(Messages.ERROR9)
    return param

  def _SetupShellInputParameter(self, shellInput):
    param = shellInput
    self.PhaseReporter.Info(Messages.INFO6.format(param))
    return param

  def _SetupRunAsLoggedInUserParameter(self, runAsLoggedInUser):
    param = runAsLoggedInUser
    logging.info(Messages.INFO10.format(runAsLoggedInUser))
    return param

  def _LogSuccess(self, phaseSuccessful):
    if phaseSuccessful:
      self.PhaseReporter.Info(Messages.INFO7)
    else:
      self.PhaseReporter.Info(Messages.INFO8)

  def _GetTempFile(self, prefixArg, suffixArg, dirPath):
    namedTempFile = NamedTemporaryFile(prefix=prefixArg, suffix=suffixArg, dir=dirPath, delete=False)
    filePath = namedTempFile.name
    namedTempFile.close()
    return filePath


class Messages(object):
  INFO1 = 'Executing Powershell Scripting Phase...'
  INFO2 = 'PowerShell script successfully created from the shell input: {0}'
  INFO3 = 'Executing the shell script...'
  INFO4 = 'Executing command: {0}'
  INFO5 = 'Removing temporary shell script'
  INFO6 = 'Powershell Input Parameter {0}'
  INFO7 = 'Execution of PowerShell Script succeeded'
  INFO8 = 'Execution of PowerShell Script failed.'
  INFO9 = 'output: {0}'
  INFO10 = 'Run As Logged In User parameter is: {0}'
  INFO11 = 'File Path parameter set to {0}'

  WARN1 = 'Temporary shell script could not be removed. You might want to manually remove it.'

  ERROR1 = 'Shell Input parameter is required'
  ERROR2 = 'File Path parameter is required'
  ERROR3 = 'Log File path could not be set. Phase will not continue.'
  ERROR4 = 'Remove Log File Parameter is required'
  ERROR5 = 'An error occured executing the Powershell script'
  ERROR6 = 'Powershell script could not be created. Phase will fail.'
  ERROR7 = 'Error: {0}'
  ERROR8 = 'Unable to create temporary file in specified path. Phase will fail.'
  ERROR9 = 'Directory does not exist and cannot be created'
  ERROR10 = 'ExitCode: {0}'
  ERROR11 = 'ErrorCode: {0}'
