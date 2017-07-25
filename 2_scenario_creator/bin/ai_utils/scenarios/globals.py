import logging
from ai_utils.ai_logging.simplelogger import AiLoggerClass

AiLoggerClass().Enable('main.py')

import itertools

PhaseCounter = itertools.count()

from ai_utils.utils.fileutils import FileUtilsClass as FileUtils
from ai_utils.utils.hostinfo import HostInfoClass as HostInfo
from ai_utils.utils.networkutils import NetworkUtilsClass as NetworkUtils
from ai_utils.utils.pathutils import PathUtilsClass as PathUtils
from ai_utils.utils.scenarioutils import ScenarioUtilsClass as ScenarioUtils
from ai_utils.utils.stringutils import StringUtilsClass as StringUtils
from ai_utils.reporter.reporter import ReporterClass, LoggerTypeClass
from ai_utils.ai_logging.utils import LoggingUtilsClass as LoggingUtils

GenericReporter = ReporterClass("", LoggerTypeClass.Generic)

def HasAttr(objectName, attribute):
  if not hasattr(objectName, attribute):
    logging.error("{0} must have attribute '{1}'".format(objectName.__name__, attribute))
    return False
  if StringUtils.IsEmptyOrNull(getattr(objectName, attribute)):
    logging.error("{0} must have non-empty attribute '{1}'".format(objectName.__name__, attribute))
    return False
  return True

class Globals:
  CriticalPhasesCount = 0
  CriticalPhaseSuccessCount = 0
  ScenarioType = None
  PhaseErrorCount = 0