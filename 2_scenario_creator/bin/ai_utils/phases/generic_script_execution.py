from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.scenarios.globals import FileUtils, PathUtils
import subprocess
import logging
import re
import os


class GenericScriptExecutionPhaseClass(AbstractPhaseClass):
    TrackerId = "PHS-de16e17b-0107-11e6-b088-d8cb8a2a09d1"
    Subject = "Generic Script Execution"
    Description = "This phase executes a specific type of script"

    def __init__(self, isPhaseCritical, scriptFile, interpreter, parameters='', successType='with_exit_code', exitCode=0, testPattern='', logFilePath=None, removeLogFile=True):
        AbstractPhaseClass.__init__(self, isPhaseCritical)
        logging.info(Messages.INFO15)
        self.Parameters = self._SetupParametersParameter(parameters)
        self.Interpreter = self._SetupInterpreterParameter(interpreter)
        self.ScriptFile = self._SetupScriptFileParameter(scriptFile)
        self.SuccessType = self._SetupSuccessTypeParameter(successType)
        self.SuccessExitCode = self._SetupExitCodeParameter(exitCode)
        self.SuccessTestPattern = self._SetupSuccessTestPatternParameter(testPattern)
        self.LogFile = self._SetupLogFilePathParameter(logFilePath)
        self.RemoveLogFileParameter = self._SetupRemoveLogFileParameterParameter(removeLogFile)
        self.ScriptOutput = ''

    def Setup(self):
        if not self.ScriptFile:
            self.PhaseReporter.Error(Messages.ERROR1)
            return False
        if not self.SuccessType:
            self.PhaseReporter.Error(Messages.ERROR2)
            return False
        if not self.Interpreter:
            self.PhaseReporter.Error(Messages.ERROR14)
            return False
        if not self._ValidateHowToCheckScriptSuccess():
            return False
        if not self.LogFile:
            self.PhaseReporter.Error(Messages.ERROR3)
            return False
        if not self.RemoveLogFileParameter:
            self.PhaseReporter.Error(Messages.ERROR4)
            return False
        return True

    def Run(self):
        exitCode = self._ExecuteScript()
        phaseSuccessful = self._CheckScriptSuccess(exitCode)
        self._LogSuccess(phaseSuccessful)
        return phaseSuccessful

    def RemoveScript(self):
        success = True
        if not FileUtils.DeleteFile(self.ScriptFile):
            success = False
            self.PhaseReporter.Warn(Messages.WARN1.format(self.ScriptFile))
        return success

    def RemoveLogFile(self):
        success = True
        if self.RemoveLogFileParameter:
            if not FileUtils.DeleteFile(self.LogFile):
                success = False
                self.PhaseReporter.Warn(Messages.WARN2.format(self.LogFile))
        else:
            logging.info(Messages.INFO14.format(self.RemoveLogFileParameter))
        return success

    def Cleanup(self):
        logging.info(Messages.INFO5)
        return self.RemoveScript() and self.RemoveLogFile()

    ###
    # Internal methods
    ##################

    def _ExecuteScript(self):
        self.PhaseReporter.Info(Messages.INFO3)
        exitCode = -1
        try:
            shellCommand = self._SetupCommand()
            logging.info(Messages.INFO4.format(shellCommand))
            exitCode = subprocess.call(shellCommand, shell=True)
            self.PhaseReporter.Info(Messages.INFO20.format(exitCode))
        except Exception as e:
            self.PhaseReporter.Error(Messages.ERROR5.format(e))
        return exitCode

    def _SetupCommand(self):
        if self.Interpreter.endswith('cmd.exe'):
            shellCommand = '"{0}" /c ""{1}" {2}" > "{3}" 2>&1'.format(self.Interpreter, self.ScriptFile, self.Parameters, self.LogFile)
        elif self.Interpreter.endswith('cmd.exe /c'):
            shellCommand = '"{0}" ""{1}" {2}" > "{3}" 2>&1'.format(self.Interpreter, self.ScriptFile, self.Parameters, self.LogFile)
        elif self.Interpreter.endswith('powershell.exe'):
            shellCommand = '"{0}" -File "{1}" {2} > "{3}" 2>&1'.format(self.Interpreter, self.ScriptFile, self.Parameters, self.LogFile)
        elif self.Interpreter.endswith('powershell.exe -File'):
            shellCommand = '"{0}" "{1}" {2} > "{3}" 2>&1'.format(self.Interpreter, self.ScriptFile, self.Parameters, self.LogFile)
        else:
            shellCommand = '"{0}" "{1}" {2} > "{3}" 2>&1'.format(self.Interpreter, self.ScriptFile, self.Parameters, self.LogFile)
        return shellCommand

    def _CheckScriptSuccess(self, exitCode):
        self.ScriptOutput = FileUtils.ReadFromFile(self.LogFile)
        self.PhaseReporter.Info(Messages.INFO12.format(self.ScriptOutput[:256]))
        if self.SuccessType == 'with_exit_code':
            success = exitCode == self.SuccessExitCode
        elif self.SuccessType == 'with_test_pattern':
            success = self._CheckScriptOutput()
        else:
            self.PhaseReporter.Error(Messages.ERROR8)
            raise ValueError(Messages.ERROR8)
        return success

    def _CheckScriptOutput(self):
        self.PhaseReporter.Info(Messages.INFO21.format(self.SuccessTestPattern))
        success = False
        if self.ScriptOutput:
            logging.info(Messages.INFO25.format(self.ScriptOutput))
            success = self._CheckIfScriptOutputIsCorrect()
            self._LogReadTestPatternSuccess(success)
        else:
            self.PhaseReporter.Info(Messages.INFO24)
        return success

    def _CheckIfScriptOutputIsCorrect(self):
        success = False
        testOutput = re.compile(self.SuccessTestPattern)
        if testOutput.search(self.ScriptOutput):
            success = True
        else:
            logging.info(Messages.INFO11.format(self.SuccessTestPattern, self.ScriptOutput))
        return success

    def _LogReadTestPatternSuccess(self, success):
        if success:
            self.PhaseReporter.Info(Messages.INFO22)
        else:
            self.PhaseReporter.Info(Messages.INFO23)

    def _LogSuccess(self, phaseSuccessful):
        if phaseSuccessful:
            self.PhaseReporter.Info(Messages.INFO6)
        else:
            self.PhaseReporter.Info(Messages.INFO13.format(self.ScriptOutput))

    ###
    # Setup Parameters
    ##################

    def _SetupScriptFileParameter(self, scriptFile):
        param = ''
        if scriptFile:
            param = self._RenameFileIfCMDInterpreter(scriptFile)
        self.PhaseReporter.Info(Messages.INFO7.format(param))
        return param

    def _RenameFileIfCMDInterpreter(self, scriptFile):
        if self.Interpreter.endswith('cmd.exe') or self.Interpreter.endswith('cmd.exe /c'):
            param = self._RenameFileToBat(scriptFile)
        elif self.Interpreter.endswith('powershell.exe') or self.Interpreter.endswith('powershell.exe -File'):
            param = self._RenameFileToPS1(scriptFile)
        else:
            param = scriptFile
        return param

    def _RenameFileToBat(self, scriptFile):
        newFileName = scriptFile + '.bat'
        return self._RenameFile(scriptFile, newFileName)

    def _RenameFileToPS1(self, scriptFile):
        newFileName = scriptFile + '.ps1'
        return self._RenameFile(scriptFile, newFileName)

    def _RenameFile(self, scriptFile, newFileName):
        param = ''
        if FileUtils.CopyFile(scriptFile, newFileName):
            FileUtils.DeleteFile(scriptFile)
            param = newFileName
        else:
            self.PhaseReporter.Error(Messages.ERROR12)
        return param

    def _SetupLogFilePathParameter(self, logFilePath):
        param = ''
        if logFilePath is None:
            param = PathUtils.GetTempFile(prefixArg='ai-so-', suffixArg='.log')
        logging.info(Messages.INFO9.format(param))
        return param

    def _SetupRemoveLogFileParameterParameter(self, removeLogFile):
        param = ''
        if removeLogFile:
            param = removeLogFile
        logging.info(Messages.INFO10.format(param))
        return param

    def _SetupSuccessTestPatternParameter(self, test_pattern):
        param = ''
        if test_pattern:
            param = test_pattern
        logging.info(Messages.INFO8.format(param))
        return param

    def _SetupParametersParameter(self, parameters):
        param = ''
        if parameters:
            param = parameters
        logging.info(Messages.INFO16.format(param))
        return param

    def _SetupInterpreterParameter(self, interpreter):
        param = ''
        if interpreter:
            interpreter = os.path.expandvars(interpreter)
            if FileUtils.Which(interpreter):
                param = interpreter
            else:
                self.PhaseReporter.Error(Messages.ERROR13.format(interpreter))
        logging.info(Messages.INFO17.format(param))
        return param

    def _SetupExitCodeParameter(self, exitCode):
        param = None
        if type(exitCode) == int:
            param = exitCode
        logging.info(Messages.INFO18.format(param))
        return param

    def _SetupSuccessTypeParameter(self, successType):
        param = ''
        if successType:
            param = successType
        logging.info(Messages.INFO19.format(param))
        return param

    def _ValidateHowToCheckScriptSuccess(self):
        success = True
        if self.SuccessType == 'with_exit_code' and type(self.SuccessExitCode) != int:
            self.PhaseReporter.Error(Messages.ERROR9.format(self.SuccessExitCode))
            success = False
        elif self.SuccessType == 'with_test_pattern' and not self.SuccessTestPattern:
            self.PhaseReporter.Error(Messages.ERROR10.format(self.SuccessExitCode))
            success = False
        elif self.SuccessType != 'with_exit_code' and self.SuccessType != 'with_test_pattern':
            success = False
            self.PhaseReporter.Error(Messages.ERROR11.format(self.SuccessType))
        return success


class Messages(object):
    INFO1 = 'Creating script from the script file input...'
    INFO2 = 'Script successfully created from the script file input: {0}'
    INFO3 = 'Executing the script...'
    INFO4 = 'Executing command: {0}'
    INFO5 = 'Removing temporal script and log file'
    INFO6 = 'Script was successfully executed.'
    INFO7 = 'Script File Parameter: {0}'
    INFO8 = 'Test Pattern Parameter: {0}'
    INFO9 = 'Script output will be stored in: {0}'
    INFO10 = 'Log File removal: {0}'
    INFO11 = 'Test pattern: "{0}" not found in "{1}"'
    INFO12 = 'Script output read from log file (256 bytes): "{0}"'
    INFO13 = 'Failed to execute script'
    INFO14 = 'Log file is not removed because of configuration. Remove Log File Parameter = {}'
    INFO15 = 'Executing Generic Script Execution phase...'
    INFO16 = 'Parameters: {0}'
    INFO17 = 'Interpreter Parameter: {0}'
    INFO18 = 'Exit Code Parameter: {0}'
    INFO19 = 'Success Type Parameter: {0}'
    INFO20 = 'Exit Code after executing the command: {0}'
    INFO21 = 'Reading command output file for test pattern: "{0}"'
    INFO22 = 'Success Test Pattern found in the command output file'
    INFO23 = 'Success Test Pattern could not be found in the command output file'
    INFO24 = 'Script output could not be read from log file (or it is empty). Script execution failed.'
    INFO25 = 'Complete script output read from log file: "{0}"'

    WARN1 = 'Temporal script could not be removed. You might want to manually remove it: {0}'
    WARN2 = 'Log file could not be removed. You might want to manually remove it: {0}'

    ERROR1 = 'Script File parameter is required'
    ERROR2 = 'Success Type parameter is required'
    ERROR3 = 'Log File path could not be set. Phase will not continue.'
    ERROR4 = 'Remove Log File parameter is required.'
    ERROR5 = 'An error occurred executing the script: {0}'
    ERROR6 = 'Script could not be created. Phase will fail.'
    ERROR8 = 'Script success could not be determined because Success Type parameter is not correctly set'
    ERROR9 = 'Success Type parameter is set to with_test_pattern, but test pattern is not correctly set: "{}". Phase will fail.'
    ERROR10 = 'Success Type parameter is set to with_exit_code, but exit code is not correctly set: {}. Phase will fail.'
    ERROR11 = 'Success Type parameter set to "{}", valid options are with_exit_code or with_test_pattern. Phase will fail.'
    ERROR12 = 'When CMD/PowerShell interpreter is used, the file should be renamed to .bat/.ps1. But that action was not successful. Phase will fail.'
    ERROR13 = 'Interpreter could not be found in the system. File does not exist: {}'
    ERROR14 = 'Interpreter parameter is required'
