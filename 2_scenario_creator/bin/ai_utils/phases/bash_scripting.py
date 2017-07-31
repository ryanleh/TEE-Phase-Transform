from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.scenarios.globals import FileUtils, PathUtils
import subprocess
import logging
import re


class BashScriptingPhaseClass(AbstractPhaseClass):
    TrackerId = "521"
    Subject = "Bash Scripting"
    Description = "This phase executes a bash script and tests if its output is correct"

    def __init__(self, isPhaseCritical, bashInput, testPattern, logFilePath=None, removeLogFile=True):
        AbstractPhaseClass.__init__(self, isPhaseCritical)
        logging.info(Messages.INFO15)
        self.BashInput = self._SetupBashInputParameter(bashInput)
        self.TestPattern = self._SetupTestPatternParameter(testPattern)
        self.LogFile = self._SetupLogFilePathParameter(logFilePath)
        self.RemoveLogFileParameter = self._SetupRemoveLogFileParameterParameter(removeLogFile)
        self.BashScriptName = ''
        self.CommandOutput = ''

    def Setup(self):
        if not self.BashInput:
            self.PhaseReporter.Error(Messages.ERROR1)
            return False
        if not self.TestPattern:
            self.PhaseReporter.Error(Messages.ERROR2)
            return False
        if not self.LogFile:
            self.PhaseReporter.Error(Messages.ERROR3)
            return False
        if not self.RemoveLogFileParameter:
            self.PhaseReporter.Error(Messages.ERROR4)
            return False
        return True

    def Run(self):
        phaseSuccessful = False
        if self._CreateBashScript():
            self._ExecuteBashScript()  # exit code not checked
            phaseSuccessful = self._CheckCommandOutput()
        self._LogSuccess(phaseSuccessful)
        return phaseSuccessful

    def RemoveBashScript(self):
        success = True
        if not FileUtils.DeleteFile(self.BashScriptName):
            success = False
            self.PhaseReporter.Warn(Messages.WARN1.format(self.BashScriptName))
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
        return self.RemoveBashScript() and self.RemoveLogFile()

    ###
    # Internal methods
    ##################

    def _CreateBashScript(self):
        logging.info(Messages.INFO1)
        success = False
        bashScript = PathUtils.GetTempFile(prefixArg='ai-bs-', suffixArg='.sh')
        if bashScript and FileUtils.WriteToFile(bashScript, self.BashInput):
            self.BashScriptName = bashScript
            success = True
            logging.info(Messages.INFO2.format(bashScript))
        else:
            self.PhaseReporter.Error(Messages.ERROR6)
        return success

    def _ExecuteBashScript(self):
        self.PhaseReporter.Info(Messages.INFO3)
        success = False
        try:
            shellCommand = 'sh "{0}" > "{1}" 2>&1'.format(self.BashScriptName, self.LogFile)
            logging.info(Messages.INFO4.format(shellCommand))
            # no problem by using shell=True because we control the command line
            success = subprocess.call(shellCommand, shell=True) == 0
        except Exception as e:
            self.PhaseReporter.Error(Messages.ERROR5.format(e))
        return success

    def _CheckCommandOutput(self):
        success = False
        commandOutput = FileUtils.ReadFromFile(self.LogFile)
        if commandOutput:
            logging.info(Messages.INFO12.format(commandOutput))
            self.CommandOutput = commandOutput
            success = self._CheckIfCommandOutputIsCorrect()
        else:
            logging.error(Messages.ERROR7)
        return success

    def _CheckIfCommandOutputIsCorrect(self):
        success = False
        testOutput = re.compile(self.TestPattern)
        if testOutput.search(self.CommandOutput):
            logging.info(Messages.INFO6.format(self.CommandOutput))
            success = True
        else:
            logging.info(Messages.INFO11.format(self.CommandOutput))
        return success

    def _LogSuccess(self, phaseSuccessful):
        if phaseSuccessful:
            self.PhaseReporter.Info(Messages.INFO6.format(self.CommandOutput))
        else:
            self.PhaseReporter.Info(Messages.INFO13.format(self.CommandOutput))

    ###
    # Setup Parameters
    ##################

    def _SetupBashInputParameter(self, bashInput):
        param = ''
        if bashInput:
            param = bashInput
        self.PhaseReporter.Info(Messages.INFO7.format(param))
        return param

    def _SetupTestPatternParameter(self, testPattern):
        param = ''
        if testPattern:
            param = testPattern
        self.PhaseReporter.Info(Messages.INFO8.format(param))
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

class Messages(object):
    INFO1 = 'Creating bash script from the bash input...'
    INFO2 = 'Bash script successfully created from the bash input: {0}'
    INFO3 = 'Executing the bash script...'
    INFO4 = 'Executing command: {0}'
    INFO5 = 'Removing temporal bash script and log file'
    INFO6 = 'Bash script was successfully executed.'
    INFO7 = 'Bash Input Parameter: {0}'
    INFO8 = 'Test Pattern Parameter: {0}'
    INFO9 = 'Command output will be stored in: {0}'
    INFO10 = 'Log File removal: {0}'
    INFO11 = 'Expected output not found in {0}'
    INFO12 = 'Command output read from log file: {0}'
    INFO13 = 'Successfully executed Bash Script. However test pattern was not found in Script output.'
    INFO14 = 'Log file is not removed because of configuration. Remove Log File Parameter = {}'
    INFO15 = 'Executing Bash Scripting phase...'

    WARN1 = 'Temporal bash script could not be removed. You might want to manually remove it: {0}'
    WARN2 = 'Log file could not be removed. You might want to manually remove it: {0}'

    ERROR1 = 'Bash Input parameter is required'
    ERROR2 = 'Test Pattern parameter is required'
    ERROR3 = 'Log File path could not be set. Phase will not continue.'
    ERROR4 = 'Remove Log File parameter is required.'
    ERROR5 = 'An error occurred executing the bash script: {0}'
    ERROR6 = 'Bash script could not be created. Phase will fail.'
    ERROR7 = 'Command output could not be read from log file. Command execution failed.'
