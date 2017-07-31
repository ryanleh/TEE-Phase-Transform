from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.utils.offensive.wmi import WMIUtilsClass
import logging

class ExecuteWMICommandPhaseClass(AbstractPhaseClass):
    TrackerId = "632"
    Subject = "Execute WMI Command"
    Description = "This phase executes an WMI command using the WMI Command-line tools"

    def __init__(self, isPhaseCritical, command):
        logging.info(Messages.INFO1)
        AbstractPhaseClass.__init__(self, isPhaseCritical)
        self.WMICommand = self._SetupCommandParameter(command)

    def Setup(self):
        if not self.WMICommand:
            self.PhaseReporter.Error(Messages.ERROR1)
            return False
        return True

    def Run(self):
        self.PhaseReporter.Info(Messages.INFO4.format(self.WMICommand))
        output = WMIUtilsClass.ExecuteWMICommand(self.WMICommand, timeout=40000)
        return self._LogSuccess(output)

    def _LogSuccess(self, output):
        if output:
            self.PhaseResult['WMIOutput'] = output
            self.PhaseReporter.Info(Messages.INFO3)
            self.PhaseReporter.Info(Messages.INFO5.format(output))
            self.PhaseReporter.Report('A WMI command was executed using the WMI Console (wmic.exe)')
            success = True
        else:
            self.PhaseReporter.Info(Messages.ERROR2)
            success = False
        return success

    def _SetupCommandParameter(self, command):
        param = command
        logging.info(Messages.INFO2.format(param))
        return param

class Messages(object):
    INFO1 = 'Executing Execute WMI Command phase...'
    INFO2 = 'Command parameter: {0}'
    INFO3 = 'WMI command was successfully executed'
    INFO4 = 'Executing WMI command: {0}'
    INFO5 = 'Command output: {0}'

    ERROR1 = 'Command parameter is required'
    ERROR2 = 'Failed to execute WMI command'
