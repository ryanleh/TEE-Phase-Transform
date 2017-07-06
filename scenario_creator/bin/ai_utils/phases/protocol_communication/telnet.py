import logging
try:
  # noinspection PyUnresolvedReferences
  import aipythonlib
except:
  logging.error('error importing aipythonlib')
from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.scenarios.globals import PathUtils

class TelnetPhaseClass(AbstractPhaseClass):
  TrackerId = "341"
  Subject = "Test Telnet"
  Description = "Test Telnet"

  def __init__(self, isPhaseCritical, remoteServer):
    AbstractPhaseClass.__init__(self, isPhaseCritical)
    self.RemoteServer = remoteServer

  def Setup(self):
    if not PathUtils.FindFile("curl.exe"):
      self.PhaseReporter.Error('curl.exe not found in path')
      return False
    return True

  def Telnet(self):
    telnetCommand = "--max-time 20 telnet://{0}".format(self.RemoteServer)
    errorCode, exitCode, stdOut, stdErr = aipythonlib.AiRunCommand("curl.exe", telnetCommand, 0)
    logging.info(locals())
    return errorCode == 0 and exitCode == 0

  def Run(self):
    phaseSuccessful = self.Telnet()
    if phaseSuccessful:
      self.PhaseReporter.Warn("Successfully telnet to {0}".format(self.RemoteServer))
    else:
      self.PhaseReporter.Info("Failed to telnet to {0}".format(self.RemoteServer))
    return phaseSuccessful
