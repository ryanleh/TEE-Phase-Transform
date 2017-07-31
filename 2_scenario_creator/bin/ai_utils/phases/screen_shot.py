import logging
try:
    # noinspection PyUnresolvedReferences
    import aipythonlib
except:
    logging.error('error importing aipythonlib')
from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.scenarios.globals import FileUtils, PathUtils

class ScreenshotPhaseClass(AbstractPhaseClass):
    TrackerId = "18"
    Subject = "Take Screenshot"
    Description = "Take Screenshot"

    def __init__(self, isPhaseCritical):
        AbstractPhaseClass.__init__(self, isPhaseCritical)
        self.ScreenshotPath = PathUtils.GetTempFile('screeshot-', '.png')
        self.ScreenshotData = None

    def Setup(self):
        if not PathUtils.FindFile("boxcutter.exe"):
            self.PhaseReporter.Error('boxcutter.exe not found in path')
            return False
        return True

    def ReadScreenshot(self):
        self.ScreenshotData = FileUtils.ReadFromFile(self.ScreenshotPath)
        return self.ScreenshotData and len(self.ScreenshotData)

    def TakeScreenshot(self):
        boxcutterCommand = '-f "{0}"'.format(self.ScreenshotPath)
        errorCode, exitCode, stdOut, stdErr = aipythonlib.AiRunCommandAsActiveLoggedInUser("boxcutter.exe", boxcutterCommand, 0)
        if errorCode == 0 and exitCode == 0:
            return self.ReadScreenshot()
        self.PhaseReporter.Error('Failed to run as active logged in user with errorCode:{0} exitCode:{1}'.format(errorCode, exitCode))
        errorCode, exitCode, stdOut, stdErr = aipythonlib.AiRunCommand("boxcutter.exe", boxcutterCommand, 0)
        if errorCode == 0 and exitCode == 0:
            return self.ReadScreenshot()
        self.PhaseReporter.Error('Failed to run in current session with errorCode:{0} exitCode:{1}'.format(errorCode, exitCode))
        return False

    def Cleanup(self):
        FileUtils.DeleteFile(self.ScreenshotPath)

    def Run(self):
        phaseSuccessful = self.TakeScreenshot()
        if phaseSuccessful:
            self.PhaseReporter.Info("Successfully saved desktop screenshot to {0}".format(self.ScreenshotPath))
        else:
            self.PhaseReporter.Info("Failed to take screenshot")
        return phaseSuccessful
