import sys
import logging
from logging.handlers import RotatingFileHandler
from ai_utils.utils.pathutils import PathUtilsClass as PathUtils

class AiLoggerClass(object):
  def __init__(self, loggingLevel=logging.INFO):
    self.LoggingLevel = loggingLevel

  def Enable(self, sourceFilepath=None):
    logfilePath = PathUtils.GetLogFilepath(sourceFilepath or 'main.py')
    logFormatter = logging.Formatter("%(asctime)s::%(message)s", datefmt='[%d/%b/%Y %H:%M:%S]')

    rootLogger = logging.getLogger('')
    rootLogger.setLevel(self.LoggingLevel)
    rootLogger.handlers = [] #reset all existing handlers else you will see double logging

    if logfilePath:
      fileHandler = RotatingFileHandler(logfilePath, maxBytes=5*1024*1024, backupCount=2)
      fileHandler.setFormatter(logFormatter)
      rootLogger.addHandler(fileHandler)

    consoleHandler = logging.StreamHandler(sys.stdout)
    consoleHandler.setFormatter(logFormatter)

    rootLogger.addHandler(consoleHandler)
