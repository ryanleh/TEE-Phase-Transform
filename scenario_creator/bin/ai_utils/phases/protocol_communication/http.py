import logging
try:
    # noinspection PyUnresolvedReferences
    import aipythonlib
except:
    logging.error('error importing aipythonlib')
from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.scenarios.globals import PathUtils

class HttpPhaseClass(AbstractPhaseClass):
    TrackerId = "72"
    Subject = "Test HTTP Communication"
    Description = "Test HTTP Communication"

    def __init__(self, isPhaseCritical, remoteServer):
        AbstractPhaseClass.__init__(self, isPhaseCritical)
        self.RemoteServer = remoteServer

    def Setup(self):
        if not PathUtils.FindFile("curl.exe"):
            self.PhaseReporter.Error('curl.exe not found in path')
            return False
        return True

    def Http(self):
        httpCommand = "--max-time 20 http://{0}".format(self.RemoteServer)
        errorCode, exitCode, stdOut, stdErr = aipythonlib.AiRunCommand("curl.exe", httpCommand, 0)
        logging.info(locals())
        return errorCode == 0 and exitCode == 0

    def Run(self):
        phaseSuccessful = self.Http()
        if phaseSuccessful:
            self.PhaseReporter.Warn("Successfully connected via http to {0}".format(self.RemoteServer))
        else:
            self.PhaseReporter.Info("Failed to connect via http to {0}".format(self.RemoteServer))
        return phaseSuccessful
