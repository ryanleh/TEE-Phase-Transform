from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.scenarios.globals import PathUtils, FileUtils, StringUtils
from ai_utils.utils.offensive.wmi import WMIUtilsClass
from ai_utils.utils.offensive.powershell import PowershellUtilsClass
import datetime
import logging
import time
import re


class PersistenceThroughWMIPhaseClass(AbstractPhaseClass):
  TrackerId = "635"
  Subject = "Persistence Through WMI"
  Description = "This phase compiles a WMI MOF file in order to automatically execute a command in order to achieve persistence once an event occurs"

  PathUtils.AddToSearchPath(r'C:\Windows\System32\WindowsPowerShell\v1.0')
  PathUtils.AddToSearchPath(r'C:\Windows\System32')
  POWERSHELL_BINARY = PathUtils.FindFile('powershell.exe')
  CMD_BINARY = PathUtils.FindFile('cmd.exe')

  def __init__(self, isPhaseCritical):
    AbstractPhaseClass.__init__(self, isPhaseCritical)
    logging.info(Messages.INFO7)
    self.OutputLogFilename = self._SetupOutputLogFilename()
    self.TestSuccessPattern = self._SetupTestPattern()
    self.EventConsumerName = self._SetupEventConsumerName()
    self.EventFilterName = self._SetupEventFilterName()
    self.EventFilterDate = self._GetEventFilterDate()

  def Setup(self):
    if not self.OutputLogFilename:
      self.PhaseReporter.Error(Messages.ERROR2)
      return False
    if not self.POWERSHELL_BINARY:
      self.PhaseReporter.Error(Messages.ERROR3)
      return False
    if not self.CMD_BINARY:
      self.PhaseReporter.Error(Messages.ERROR4)
      return False
    if not self.EventFilterDate or len(self.EventFilterDate) != 6:
      self.PhaseReporter.Error(Messages.ERROR11)
      return False
    return True

  def Run(self):
    success = self._ExecutePhase()
    self._LogResults(success)
    return success

  def Cleanup(self):
    FileUtils.DeleteFile(self.OutputLogFilename)
    self._RemoveMOFEvent()

  ###
  # Internal Methods
  ##################

  def _ExecutePhase(self):
    self.PhaseSuccess = False
    MOFContents = self.MOF_CONTENTS.format(self.CMD_BINARY.replace('\\', '\\\\'),
                                           self.OutputLogFilename.replace('\\', '\\\\'),
                                           self.EventConsumerName,
                                           self.EventFilterName,
                                           eventFilterDate=self.EventFilterDate)
    logging.info(Messages.INFO6.format(MOFContents))
    self.PhaseReporter.Info(Messages.INFO8)
    if WMIUtilsClass.CompileMOFFile(MOFContents):
      time.sleep(10)  # sleep some prudential time to wait from MOF compilation to event trigger
      self.PhaseSuccess = self._CheckEventConsumerSuccess()
    else:
      self.PhaseReporter.Error(Messages.ERROR8)
    return self.PhaseSuccess

  def _CheckEventConsumerSuccess(self):
    self.PhaseReporter.Info(Messages.INFO9)
    success = False
    if FileUtils.FileExists(self.OutputLogFilename):
      EventConsumerOutput = FileUtils.ReadFromFile(self.OutputLogFilename)
      pattern = re.compile(self.TestSuccessPattern)
      if pattern and pattern.search(EventConsumerOutput):
        success = True
      else:
        self.PhaseReporter.Error(Messages.ERROR5)
        logging.error(Messages.ERROR6.format(self.OutputLogFilename))
    else:
      self.PhaseReporter.Error(Messages.ERROR7)
    return success

  def _GetEventFilterDate(self):
    """
    The Event is scheduled to be executed after 5 seconds of retrieving the system time.
    If time is later than 23:59:53, the phase will fail because we do not want to handle
    the change of the day of the month.

    Returns: (list) [year, month, day, hour, minute, second]
    """
    param = []
    now = datetime.datetime.now()
    # datetime.second => range(60) and datetime.minute => range(60) and datetime.hour => range(24)
    if now.second > 50 and now.minute == 59 and now.hour == 23:
      self.PhaseReporter.Error(Messages.ERROR9)
    elif now.second > 50 and now.minute == 59:
      param = [now.year, now.month, now.day, now.hour + 1, 0, 0]
    elif now.second > 50:
      param = [now.year, now.month, now.day, now.hour, now.minute + 1, 0]
    else:
      param = [now.year, now.month, now.day, now.hour, now.minute, now.second + 5]
    return param

  def _RemoveMOFEvent(self):
    if self.PhaseSuccess:
      eventFilterExitCode = self._RemoveEventFilter()
      eventConsumerExitCode = self._RemoveEventConsumer()
      bindingExitCode = self._RemoveBinding()
      return eventFilterExitCode == 0 and eventConsumerExitCode == 0 and bindingExitCode == 0
    return True

  def _RemoveEventFilter(self):
    removeEventFilterCommand = 'gwmi -Namespace root\\subscription -Class __EventFilter | where {{$_.name -eq \'{0}\'}} | Remove-WmiObject'.format(self.EventFilterName)
    output, eventFilterExitCode = PowershellUtilsClass.ExecutePowerShellCommand(removeEventFilterCommand, timeout=30000)
    self._LogMOFEventRemovalSuccess('Event Filter', output, eventFilterExitCode, removeEventFilterCommand)
    return eventFilterExitCode

  def _RemoveEventConsumer(self):
    removeEventConsumerCommand = 'gwmi -Namespace root\\subscription -Class ActiveScriptEventConsumer | where {{$_.name -eq \'{0}\'}} | Remove-WmiObject'.format(self.EventConsumerName)
    output, eventConsumerExitCode = PowershellUtilsClass.ExecutePowerShellCommand(removeEventConsumerCommand, timeout=30000)
    self._LogMOFEventRemovalSuccess('Event Consumer', output, eventConsumerExitCode, removeEventConsumerCommand)
    return eventConsumerExitCode

  def _RemoveBinding(self):
    removeBindingCommand = 'gwmi -Namespace root\\subscription -Class __FilterToConsumerBinding | where {{$_.filter -like \'*{0}*\'}} | Remove-WmiObject'.format(self.EventFilterName)
    output, bindingExitCode = PowershellUtilsClass.ExecutePowerShellCommand(removeBindingCommand, timeout=30000)
    self._LogMOFEventRemovalSuccess('Binding', output, bindingExitCode, removeBindingCommand)
    return removeBindingCommand

  def _SetupTestPattern(self):
    param = 'AttackIQ WMI Persistence'
    logging.info(Messages.INFO2.format(param))
    return param

  def _SetupOutputLogFilename(self):
    param = PathUtils.GetTempFile('ai-', '.log')
    if param:
      logging.info(Messages.INFO4.format(param))
    return param

  def _SetupEventConsumerName(self):
    param = StringUtils.GetRandomString() + '_AICreateFile'
    self.PhaseReporter.Info(Messages.INFO10.format(param))
    return param

  def _SetupEventFilterName(self):
    param = StringUtils.GetRandomString() + '_AIAutostartFilter'
    self.PhaseReporter.Info(Messages.INFO11.format(param))
    return param

  def _LogMOFEventRemovalSuccess(self, eventType, output, exitCode, command):
    logging.info(Messages.INFO12.format(eventType, exitCode, output))
    if exitCode != 0:
      self.PhaseReporter.Error(Messages.ERROR10.format(eventType, command))
    else:
      self.PhaseReporter.Info(Messages.INFO13.format(eventType))

  def _LogResults(self, success):
    if success:
      self.PhaseReporter.Info(Messages.INFO3)
      self.PhaseReporter.Report('A WMI Event registered compiling a MOF script was executed once the system time reached certain date')
    else:
      self.PhaseReporter.Info(Messages.INFO5)

  MOF_CONTENTS = r'''#pragma namespace ("\\\\.\\root\\subscription")

instance of ActiveScriptEventConsumer as $Consumer
{{
    Name = "{2}";
    ScriptingEngine = "VBScript";
    ScriptText =
        "Set objShell = CreateObject(\"WScript.Shell\") \n"
        "objShell.Exec(\"""{0}"" /c echo AttackIQ WMI Persistence > ""{1}""\")\n";
}};

instance of __EventFilter as $Filter
{{
    Name = "{3}";
    QueryLanguage = "WQL";
    EventNamespace = "root\\cimv2";
    Query =
          "SELECT * FROM __InstanceModificationEvent "
          "WHERE TargetInstance ISA 'Win32_LocalTime' AND "
          "TargetInstance.Year = {eventFilterDate[0]} AND "
          "TargetInstance.Month = {eventFilterDate[1]} AND "
          "TargetInstance.Day = {eventFilterDate[2]} AND "
          "TargetInstance.Hour = {eventFilterDate[3]} AND "
          "TargetInstance.Minute = {eventFilterDate[4]} AND "
          "TargetInstance.Second = {eventFilterDate[5]}";
}};

instance of __FilterToConsumerBinding
{{
    Filter = $Filter;
    Consumer = $Consumer;
}};'''

class Messages(object):
  INFO2 = 'Test pattern: {0}'
  INFO3 = 'Persistence successfully achieved through MOF file compilation'
  INFO4 = 'Output Log File: {0}'
  INFO5 = 'Failed to achieve persistence through MOF file compilation'
  INFO6 = 'MOF contents: {0}'
  INFO7 = 'Executing Persistence Through WMI phase...'
  INFO8 = 'Compiling MOF file...'
  INFO9 = 'Checking if Event Consumer was correctly executed...'
  INFO10 = 'Event Consumer name: {}'
  INFO11 = 'Event Filter name: {}'
  INFO12 = '{} removal: Exit Code: {}, Output: {}'
  INFO13 = '{} successfully removed'

  ERROR1 = 'MOF file could not be created. This step is required to execute the phase.'
  ERROR2 = 'Output Log File could not be created. This step is required to execute the phase.'
  ERROR3 = 'Powershell binary could not be found in the operating system. This step is required to execute the phase.'
  ERROR4 = 'CMD binary could not be found in the operating system. This step is required to execute the phase.'
  ERROR5 = 'Test Success Pattern could not be found in command output file. Event Consumer has failed.'
  ERROR6 = 'Output Log File contents: {0}'
  ERROR7 = 'Output Log File has not been created. This means that the Event Consumer has failed.'
  ERROR8 = 'MOF file could not be compiled'
  ERROR9 = 'Event is not scheduled if system time is later than 23h:59m:53s. Phase will fail.'
  ERROR10 = '{} could not be removed. Try manually executing this PowerShell command: {}'
  ERROR11 = 'Date for scheduling the WMI event could not be set. Phase will fail.'
