import logging
from ai_utils.phases.abstract_phase import AbstractPhaseClass
try:
  from winappdbg import System
except Exception, e:
  logging.error(e)

class GetRunningProcessesPhaseClass(AbstractPhaseClass):
  TrackerId = "184"
  Subject = "Get All Running Processes"
  Description = "Get All Running Processes"

  def __init__(self, isPhaseCritical):
    AbstractPhaseClass.__init__(self, isPhaseCritical)
    self.SystemObject = System()
    self.RunningProcessesOut = []

  def GetRunningProcesses(self):
    if not self.SystemObject:
      logging.info('Failed to get SystemObject')
      return False
    for process in self.SystemObject:
      processInfo = (process.get_pid(), process.get_filename())
      #logging.info('Found pid:{0} name:{1}'.format(processInfo[0], processInfo[1]))
      self.RunningProcessesOut.append(processInfo)
    return len(self.RunningProcessesOut) > 0

  def Run(self):
    phaseSuccessful = self.GetRunningProcesses()
    if phaseSuccessful:
      self.PhaseResult['total_running_processes'] = len(self.RunningProcessesOut)
      self.PhaseReporter.Info('Successfully collected all the running processes')
    else:
      self.PhaseReporter.Info('Failed to collect all running processes')
    return phaseSuccessful