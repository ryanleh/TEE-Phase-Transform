import os
import time
import json
import logging
import itertools
from ai_utils.utils.pathutils import PathUtilsClass
aipythonlib_imported = False
try:
    # noinspection PyUnresolvedReferences
    import aipythonlib
    aipythonlib_imported = True
except:
    logging.warn('could not import aipythonlib')
from ai_utils.ai_types import AI_SIMPLE_TRACE_TYPE

Logger = aipythonlib.AiLoggerClass() if aipythonlib_imported else None
LoggerInitialized = Logger.Initialize() if Logger else False


class LoggerTypeClass:

    Phase = 1
    Scenario = 2
    Generic = 3

    def __init__(self, loggerType):
        assert 1 <=loggerType <=3
        self.LoggerType = loggerType

    def IsPhaseLogger(self):
        return self.LoggerType == LoggerTypeClass.Phase

    def IsScenarioLogger(self):
        return self.LoggerType == LoggerTypeClass.Scenario

    def IsGenericLogger(self):
        return self.LoggerType == LoggerTypeClass.Generic


class ReporterClass(object):

    def __init__(self, trackerId, loggerType):
        self.LoggerType = LoggerTypeClass(loggerType)
        self.TrackerId = trackerId
        self.JobId = os.getenv('SCHEDULED_JOBID') or ''
        self.LogCount = itertools.count()
        self.PhaseNumber = 0

    def GetTraceRecordMessage(self, traceMessage):
        traceRecord = {
          'ai_log_time' : int(time.time() * 1000),
          'ai_log_count' : self.LogCount.next(),
          'ai_tracker_id' : self.TrackerId,
          'ai_phase_number' : self.PhaseNumber,
          'ai_message' : str(traceMessage)
        }
        return json.dumps(traceRecord, indent=2)

    def Log(self, traceLevel, traceMessage):
        """
        TraceLevel has to only one of these
        'debug', 'info', 'warning', 'error'
        """
        if traceLevel not in AI_SIMPLE_TRACE_TYPE:
            raise Exception('Invalid Trace Level {0}'.format(traceLevel))
        traceRecord = self.GetTraceRecordMessage(traceMessage)
        logging.log(AI_SIMPLE_TRACE_TYPE[traceLevel][0], traceRecord)
        if LoggerInitialized and self.JobId:
            if self.LoggerType.IsPhaseLogger():
                Logger.LogPhaseTrace(self.JobId, self.TrackerId, AI_SIMPLE_TRACE_TYPE[traceLevel][1], traceRecord)
            elif self.LoggerType.IsScenarioLogger() or self.LoggerType.IsGenericLogger():
                Logger.LogScenarioTrace(self.JobId, self.TrackerId, AI_SIMPLE_TRACE_TYPE[traceLevel][1], traceRecord)

    def Debug(self, traceMessage):
        self.Log('debug', traceMessage)

    def Info(self, traceMessage):
        self.Log('info', traceMessage)

    def Warn(self, traceMessage):
        self.Log('warning', traceMessage)

    def Error(self, traceMessage):
        self.Log('error', traceMessage)

    def Report(self, traceMessage):
        self.Log('report', traceMessage)

    def Mitigation(self, traceMessage):
        self.Log('mitigation', traceMessage)
