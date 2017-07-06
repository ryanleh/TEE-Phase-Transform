from ai_utils.phases.abstract_phase import AbstractPhaseClass
import logging
try:
  from ctypes import windll, GetLastError
except:
  logging.error("error importing windll")

class CreateMutexPhaseClass(AbstractPhaseClass):
  TrackerId = "830"
  Subject = "Create Mutex"
  Description = "This phase creates a mutex object with a specific name"

  ERROR_ALREADY_EXISTS = 183

  def __init__(self, isPhaseCritical, mutexNamesList):
    AbstractPhaseClass.__init__(self, isPhaseCritical)
    self.MutexNamesParameter = self._SetupMutexNamesParameter(mutexNamesList)

  def Setup(self):
    if not self.MutexNamesParameter:
      self.PhaseReporter.Error(Messages.ERROR1)
      return False
    for mutexName in self.MutexNamesParameter:
      if not mutexName:
        self.PhaseReporter.Error(Messages.ERROR5)
        return False
    return True

  def Run(self):
    securityCheckPassed = self._ExecutePhase()
    self._LogResults(securityCheckPassed)
    return securityCheckPassed

  def Cleanup(self):
    return True

  ###
  # Internal Methods
  ##################

  def _ExecutePhase(self):
    self.PhaseReporter.Info(Messages.INFO4)
    successfulMutexes = 0
    for mutexName in self.MutexNamesParameter:
      if self._CreateTemporalMutex(mutexName):
        successfulMutexes += 1
    return successfulMutexes != 0

  def _CreateTemporalMutex(self, mutexName):
    self.PhaseReporter.Info(Messages.INFO5.format(mutexName))
    mutexHandle = self._CreateMutex(mutexName)
    success = True if mutexName else False
    if success and not self._MutexAlreadyExisted(mutexName):
      self._RemoveMutex(mutexName, mutexHandle)
    return success

  def _CreateMutex(self, mutexName):
    mutexHandle = 0
    try:
      mutexHandle = windll.kernel32.CreateMutexA(None, True, mutexName)
      if mutexHandle:
        self.PhaseReporter.Info(Messages.INFO6.format(mutexName))
      else:
        self.PhaseReporter.Info(Messages.INFO7.format(mutexName))
    except Exception as e:
      self.PhaseReporter.Error(Messages.ERROR2.format(mutexName, e))
    return mutexHandle

  def _MutexAlreadyExisted(self, mutexName):
    alreadyExists = False
    if GetLastError() == self.ERROR_ALREADY_EXISTS:
      self.PhaseReporter.Warn(Messages.WARN1.format(mutexName))
      alreadyExists = True
    return alreadyExists

  def _RemoveMutex(self, mutexName, mutexHandle):
    success = False
    try:
      if windll.kernel32.CloseHandle(mutexHandle):
        self.PhaseReporter.Info(Messages.INFO8.format(mutexName))
        success = True
      else:
        self.PhaseReporter.Error(Messages.ERROR3.format(mutexName, GetLastError()))
    except Exception as e:
      self.PhaseReporter.Error(Messages.ERROR4.format(mutexName, e))
    return success

  def _SetupMutexNamesParameter(self, mutexNamesList):
    param = ''
    if mutexNamesList:
      param = mutexNamesList
      logging.info(Messages.INFO1.format(param))
    return param

  def _LogResults(self, securityCheckPassed):
    if securityCheckPassed:
      self.PhaseReporter.Info(Messages.INFO2)
    else:
      self.PhaseReporter.Info(Messages.INFO3)

class Messages(object):
  INFO1 = 'First Parameter: {0}'
  INFO2 = 'At least one mutex was successfully created'
  INFO3 = 'Failed to create at least one mutex'
  INFO4 = 'Creating mutexes...'
  INFO5 = 'Creating mutex {0}'
  INFO6 = 'Mutex {0} successfully created'
  INFO7 = 'Mutex {0} could not be created'
  INFO8 = 'Mutex {0} successfully removed'

  WARN1 = 'Mutex {0} already existed. It will not be removed'

  ERROR1 = 'Mutex Names Parameter is required'
  ERROR2 = 'An error occurred creating the {0} mutex. Error: {1}'
  ERROR3 = 'Mutex {0} could not be removed. Last Error: {1}'
  ERROR4 = 'An error occurred removing the {0} mutex. Error: {1}'
  ERROR5 = 'Mutex names can not be empty. Phase will fail'
