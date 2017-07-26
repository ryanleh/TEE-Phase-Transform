import logging
try:
  # noinspection PyUnresolvedReferences
  import aipythonlib
except:
  logging.error('error importing aipythonlib')
from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.scenarios.globals import PathUtils

class PingPhaseClass(AbstractPhaseClass):
  TrackerId = "71"
  Subject = "Test Ping"
  Description = "Test Ping"

  def __init__(self, isPhaseCritical, remoteServer):
    AbstractPhaseClass.__init__(self, isPhaseCritical)
    self.RemoteServer = remoteServer

  def Setup(self):
    PathUtils.AddToSearchPath('%WINDIR%\\System32')
    if not PathUtils.FindFile("ping.exe"):
      self.PhaseReporter.Error('ping.exe not found in path')
      return False
    return True

  def Ping(self):
    errorCode, exitCode, stdOut, stdErr = aipythonlib.AiRunCommand("ping.exe", self.RemoteServer, 0)
    logging.info(locals())
    return errorCode == 0 and exitCode == 0

  def Run(self):
    phaseSuccessful = self.Ping()
    if phaseSuccessful:
      self.PhaseReporter.Warn("Successfully pinged {0}".format(self.RemoteServer))
    else:
      self.PhaseReporter.Info("Failed to ping {0}".format(self.RemoteServer))
    return phaseSuccessful
