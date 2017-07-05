import time
import json
import logging
from ai_utils.reporter.reporter import ReporterClass, Logger, LoggerInitialized, LoggerTypeClass
from ai_utils.perf.stopwatch import StopWatchClass
from ai_utils.scenarios.globals import Globals
from ai_utils.ai_types import AI_OUTCOME_TYPE

class ScenarioReporterClass(ReporterClass):
  def __init__(self, trackerId):
    ReporterClass.__init__(self, trackerId, LoggerTypeClass.Scenario)
    self.StopWatch = StopWatchClass()
    self.StopWatch.Start()

  def ReportVerdict(self, criticalPhasesSuccessful):
    scenarioOutcome = self._SetScenarioOutcome(criticalPhasesSuccessful)
    scenarioResult = {
      'ai_log_time': int (time.time()*1000),
      'ai_total_time_taken': self.StopWatch.Elapsed(),
      'ai_tracker_id': self.TrackerId,
      'ai_scenario_outcome': scenarioOutcome,
      'ai_critical_phases_successful': criticalPhasesSuccessful
    }
    resultRecord = json.dumps(scenarioResult, indent=2)
    logging.info(resultRecord)
    if LoggerInitialized and self.JobId:
      Logger.LogScenarioResult(str(self.JobId), str(self.TrackerId), int(scenarioOutcome), str(resultRecord))

  def _SetScenarioOutcome(self, criticalPhasesSuccessful):  # this method has repeated code to humanly explain the logic
    if Globals.ScenarioType == 1:  # the scenario is an Attack
      securityControlsSuccessful = criticalPhasesSuccessful == 0
      attackSuccessful = AI_OUTCOME_TYPE["OUTCOME_PASSED"] if securityControlsSuccessful \
          else AI_OUTCOME_TYPE["OUTCOME_FAILED"]
      return attackSuccessful
    elif Globals.ScenarioType == 2:  # the scenario is a Validation
      validationSuccessful = Globals.CriticalPhasesCount == Globals.CriticalPhaseSuccessCount
      validationSuccessful = AI_OUTCOME_TYPE["OUTCOME_PASSED"] if validationSuccessful \
          else AI_OUTCOME_TYPE["OUTCOME_FAILED"]
      return validationSuccessful
    else:
      logging.error('Scenario type is not correctly defined. Scenario outcome will be invalid')
    return AI_OUTCOME_TYPE['OUTCOME_INVALID']