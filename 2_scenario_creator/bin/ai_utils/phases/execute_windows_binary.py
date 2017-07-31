from ai_utils.phases.abstract_phase import AbstractPhaseClass
import logging
try:
    import aipythonlib
except ImportError as e:
    logging.error('aipythonlib module could not be imported. Error: {0}'.format(e))

class ExecuteWindowsBinaryPhaseClass(AbstractPhaseClass):
    TrackerId = "695"
    Subject = "Execute Windows Binary"
    Description = "This phase executes a windows binary"

    def __init__(self, isPhaseCritical, binary, arguments='', timeout=5000):
        AbstractPhaseClass.__init__(self, isPhaseCritical)
        logging.info(Messages.INFO3)
        self.Binary = self._SetupBinaryParameter(binary)
        self.Arguments = self._SetupArgumentsParameter(arguments)
        self.Timeout = self._SetupTimeoutParameter(timeout)

    def Setup(self):
        if not self.Binary:
            self.PhaseReporter.Error(Messages.ERROR1)
            return False
        return True

    def Run(self):
        success = self._ExecuteBinary()
        self._LogSuccess(success)
        return success

    ###
    # Internal Methods
    ##################

    def _ExecuteBinary(self):
        self.PhaseReporter.Info(Messages.INFO4.format(self.Binary, self.Arguments))
        success = False
        timeout = self.Timeout
        errorCode, exitCode, stdOut, stdError = aipythonlib.AiRunCommand(self.Binary, self.Arguments, timeout)
        if errorCode == 0 and stdError == '' and exitCode == 0:
            success = True
            self.PhaseReporter.Info(Messages.INFO8.format(exitCode, errorCode, stdError))
            self.PhaseReporter.Info(Messages.INFO5.format(stdOut))
        else:
            self.PhaseReporter.Info(Messages.ERROR2.format(exitCode, errorCode, stdOut, stdError))
        return success

    def _SetupBinaryParameter(self, binaryParameter):
        param = ''
        if binaryParameter:
            param = binaryParameter
        logging.info(Messages.INFO1.format(param))
        return param

    def _SetupArgumentsParameter(self, argumentsParameter):
        param = ''
        if argumentsParameter:
            param = argumentsParameter
        logging.info(Messages.INFO2.format(param))
        return param

    def _SetupTimeoutParameter(self, timeout):
        param = 5000
        if timeout and type(timeout) == int:
            param = timeout
        else:
            logging.info(Messages.INFO10)
        logging.info(Messages.INFO2.format(param))
        return param

    def _LogSuccess(self, success):
        if success:
            self.PhaseReporter.Info(Messages.INFO6)
        else:
            self.PhaseReporter.Info(Messages.INFO7)


class Messages(object):
    INFO1 = 'Binary parameter: {0}'
    INFO2 = 'Arguments parameter: {0}'
    INFO3 = 'Executing Execute Windows Binary phase...'
    INFO4 = 'Executing: {0} {1}'
    INFO5 = 'Command execution output: {0}'
    INFO6 = 'Binary was successfully executed'
    INFO7 = 'Failed to execute binary'
    INFO8 = 'Binary successfully executed. Exit Code: {0}, Error Code: {1}, Error Message: {2}'
    INFO9 = 'Timeout Parameter: {}'
    INFO10 = 'Setting timeout to 5 seconds'

    ERROR1 = 'Binary parameter is required.'
    ERROR2 = 'Binary could not be executed. Exit Code: {0}, Error Code: {1}, Command Output: {2}, Error Message: {3}'
