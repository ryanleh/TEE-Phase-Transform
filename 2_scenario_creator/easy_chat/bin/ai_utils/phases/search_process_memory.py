import logging
import re
try:
  from winappdbg import Process, RegExpPattern
except ImportError, e:
  logging.error('error importing winappdbg')
from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.scenarios.globals import StringUtils

class SearchProcessMemoryPhaseClass(AbstractPhaseClass):
  TrackerId = "185"
  Subject = "Search Process Memory for Pattern"
  Description = "Search Process Memory for Pattern"

  def __init__(self, isPhaseCritical, commaSeparatedListOfProcessNamePatterns, commaSeparatedListOfDataPatterns, listOfRunningProcessTuples, maximumHitsToReturn = 1, encoding = None):
    AbstractPhaseClass.__init__(self, isPhaseCritical)
    self.ListOfProcessNamePatterns = StringUtils.SplitAndTrim(commaSeparatedListOfProcessNamePatterns)
    self.ListOfDataPatterns = StringUtils.SplitAndTrim(commaSeparatedListOfDataPatterns)
    self.RunningProcesses = listOfRunningProcessTuples
    self.Hits = []
    self.MaximumHitsToReturn = maximumHitsToReturn
    self.HitCount = 0
    self.Encoding = encoding

  def Setup(self):
    if not self.ListOfProcessNamePatterns or len(self.ListOfProcessNamePatterns) == 0:
      logging.info('Invalid list of process name patterns passed')
      return False
    if not self.ListOfDataPatterns or len(self.ListOfDataPatterns) == 0:
      logging.info('Invalid list of string patterns passed')
      return False
    if not self.RunningProcesses or len(self.RunningProcesses) == 0:
      logging.info('Invalid list of running processes')
      return False
    return True

  def HitsWithLimits(self):
    return len(self.Hits) < self.MaximumHitsToReturn

  def SearchProcess(self, processInfo, searchPattern):
    logging.info('Searching in pid:{0} name:{1} for searchPattern {2}'.format(processInfo[0], processInfo[1], searchPattern))
    process = Process(processInfo[0])
    regexFlags = re.I
    if self.Encoding:
      searchPattern = searchPattern.encode(self.Encoding)
      regexFlags |= re.U
    patternObject = RegExpPattern(searchPattern, regexFlags)
    hits = process.search(patternObject)
    for hit in hits:
      if self.HitsWithLimits():
        hitToReport = processInfo + hit
        logging.info('hit[{0}]:{1}'.format(self.HitCount, hitToReport))
        self.Hits.append(hitToReport)
        self.HitCount += 1
      else:
        break
    if len(self.Hits) > 0:
      self.PhaseReporter.Info('Pattern has been found {} times in process PID: {}, Name: {}'.format(len(self.Hits), processInfo[0], processInfo[1]))
    return len(self.Hits) > 0

  def SearchRunningProcesses(self):
    for processInfo in self.RunningProcesses:
      for processNamePattern in self.ListOfProcessNamePatterns:
        for searchPattern in self.ListOfDataPatterns:
          if not self.HitsWithLimits():
            return len(self.Hits) > 0
          if StringUtils.Match(processNamePattern, processInfo[1]):

            self.SearchProcess(processInfo, searchPattern)
    return len(self.Hits) > 0

  def Run(self):
    phaseSuccessful = self.SearchRunningProcesses()
    if phaseSuccessful:
      self.PhaseResult['hits'] = str(self.Hits)
      self.PhaseReporter.Info('Successfully collected {0} search patterns from running processes'.format(len(self.Hits)))
      self.PhaseReporter.Report('Asset\'s processes memory was scrapped and searched data was found {} times'.format(self.HitCount))
    else:
      self.PhaseReporter.Info('Failed to collect requested search pattens from running processes')
    return phaseSuccessful