import logging
from ai_utils.reporter.phase_reporter import PhaseReporterClass
from ai_utils.scenarios.globals import Globals, HasAttr

# noinspection PyUnresolvedReferences,PyUnresolvedReferences
class AbstractPhaseClass(object):
  def __init__(self, isPhaseCritical):
    if not self.IsValidPhaseClass():
      raise Exception('Phase class is missing some mandatory attributes')
    self.IsCritical = isPhaseCritical
    if self.IsCritical:
      Globals.CriticalPhasesCount += 1
    self.Successful = False
    self.PhaseReporter = PhaseReporterClass(self.TrackerId, self.IsCritical)
    '''this dict is to collect custom data phase want to return'''
    self.PhaseResult = {}

  @classmethod
  def IsValidPhaseClass(cls):
    return HasAttr(cls, 'TrackerId') and HasAttr(cls, 'Subject') and HasAttr(cls, 'Description')

  def Setup(self):
    """Override it to implement your phases specific argument validation and other setup"""
    return True

  def Cleanup(self):
    """Override this method to provide your phase related cleanup"""
    return True

  def Run(self):
    """Override to implement your Phase execution
    Should return True if Phase is successful else it should return False"""
    raise NotImplementedError('This is an abstract method and should be overridden')

  def Execute(self):
    try:
      self.PhaseReporter.ReportStart()
      if self.Setup():
        self.Successful = self.Run()
      else:
        self.PhaseReporter.Error('This phase was blocked due to invalid arguments')
    except Exception, e:
      logging.exception(e)
      Globals.PhaseErrorCount += 1
    finally:
      self.Cleanup()
      if self.Successful and self.IsCritical:
        Globals.CriticalPhaseSuccessCount += 1
      self.PhaseReporter.ReportOutcome(self.Successful, self.PhaseResult)
      return self.Successful