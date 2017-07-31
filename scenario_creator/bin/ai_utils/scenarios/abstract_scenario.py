from ai_utils.reporter.scenario_reporter import ScenarioReporterClass
from ai_utils.scenarios.globals import ScenarioUtils
from ai_utils.scenarios.globals import Globals, HasAttr
import logging


class AbstractScenarioClass(object):
    def __init__(self):
        if not self.IsValidScenarioClass():
            raise Exception('Scenario class is missing some mandatory attributes (TrackerId, Subject or Description)')
        # noinspection PyUnresolvedReferences
        self.ScenarioReporter = ScenarioReporterClass(self.TrackerId)
        success, error_msg = ScenarioUtils.ValidOS()
        if not success:
            self.ScenarioReporter.ReportVerdict(Globals.CriticalPhaseSuccessCount)  # this is required to end scenario execution in FireDrill UI
            raise RuntimeError(error_msg)

    @classmethod
    def IsValidScenarioClass(cls):
        return HasAttr(cls, 'TrackerId') and HasAttr(cls, 'Subject') and HasAttr(cls, 'Description')

    # noinspection PyMethodMayBeStatic
    def Setup(self):
        """Override this method to your scenario related setup"""
        return True

    # noinspection PyMethodMayBeStatic
    def Cleanup(self):
        """Override this method to your scenario related cleanup"""
        return True

    def Run(self):
        """Override this method to implement your Scenario
        Return void"""
        raise NotImplementedError('This is an abstract method and should be overwritten')

    def Execute(self):
        exitCode = 0
        try:
            if self.Setup():
                self.Run()
        except Exception as e:
            self.ScenarioReporter.Error('Scenario errored due to {0}'.format(e))
            logging.exception(e)
            exitCode = 1
        finally:
            self.Cleanup()
            self.ScenarioReporter.ReportVerdict(Globals.CriticalPhaseSuccessCount)
            if Globals.PhaseErrorCount:
                exitCode = 1
            return exitCode
