import time
import json
import logging
from ai_utils.scenarios.globals import PhaseCounter
from ai_utils.reporter.reporter import ReporterClass, Logger, LoggerInitialized, LoggerTypeClass
from ai_utils.perf.stopwatch import StopWatchClass
from ai_utils.ai_types import AI_OUTCOME_TYPE

class PhaseReporterClass(ReporterClass):
  def __init__(self, trackerId, isCritical):
    ReporterClass.__init__(self, trackerId, LoggerTypeClass.Phase)
    assert isinstance(isCritical, bool)
    self.IsCritical = isCritical
    self.PhaseNumber = PhaseCounter.next()
    self.StopWatch = StopWatchClass()
    self.StopWatch.Start()

  def ReportStart(self):
    phaseResult = {
      'ai_phase_is_critical' : int(self.IsCritical),
      'ai_log_time' : int (time.time()*1000),
      'ai_tracker_id' : self.TrackerId,
      'ai_phase_number' : self.PhaseNumber
    }
    resultRecord = json.dumps(phaseResult, indent=2)
    logging.info(resultRecord)
    if LoggerInitialized and self.JobId:
      Logger.LogPhaseResult(self.JobId, self.TrackerId, 0, resultRecord)

  def ReportOutcome(self, isSuccess, phaseResult):
    assert isinstance(phaseResult, dict)
    if isSuccess:
      phaseOutcome = AI_OUTCOME_TYPE["OUTCOME_PASSED"]
    else:
      phaseOutcome = AI_OUTCOME_TYPE["OUTCOME_FAILED"]
    finalResult = {
      'ai_phase_is_critical' : int(self.IsCritical),
      'ai_log_time' : int (time.time()*1000),
      'ai_total_time_taken' : self.StopWatch.Elapsed(),
      'ai_tracker_id' : self.TrackerId,
      'ai_phase_outcome' : phaseOutcome,
      'ai_phase_number' : self.PhaseNumber,
      'ai_phase_result' : phaseResult
    }
    resultRecord = json.dumps(finalResult, indent=2)
    logging.info(resultRecord)
    if LoggerInitialized and self.JobId:
      Logger.LogPhaseResult(self.JobId, self.TrackerId, phaseOutcome, resultRecord)
