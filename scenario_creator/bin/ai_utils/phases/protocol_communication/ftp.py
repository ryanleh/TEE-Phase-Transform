import logging
try:
    # noinspection PyUnresolvedReferences
    import aipythonlib
except:
    logging.error('error importing aipythonlib')
from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.scenarios.globals import PathUtils

class FtpPhaseClass(AbstractPhaseClass):
    TrackerId = "73"
    Subject = "Test FTP Communication"
    Description = "Test FTP Communication"

    def __init__(self, isPhaseCritical, remoteServer):
        AbstractPhaseClass.__init__(self, isPhaseCritical)
        self.RemoteServer = remoteServer

    def Setup(self):
        if not PathUtils.FindFile("curl.exe"):
            self.PhaseReporter.Error('curl.exe not found in path')
            return False
        return True

    def Ftp(self):
        ftpCommand = "--max-time 20 ftp://{0}".format(self.RemoteServer)
        errorCode, exitCode, stdOut, stdErr = aipythonlib.AiRunCommand("curl.exe", ftpCommand, 0)
        logging.info(locals())
        return errorCode == 0 and exitCode == 0

    def Run(self):
        phaseSuccessful = self.Ftp()
        if phaseSuccessful:
            self.PhaseReporter.Warn("Successfully ftp to {0}".format(self.RemoteServer))
        else:
            self.PhaseReporter.Info("Failed to ftp to {0}".format(self.RemoteServer))
        return phaseSuccessful
