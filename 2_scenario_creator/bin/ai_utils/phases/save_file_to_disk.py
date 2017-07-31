import logging
from os import path
from os.path import join
from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.scenarios.globals import FileUtils, PathUtils, StringUtils

class SaveFileToDiskPhaseClass(AbstractPhaseClass):
    TrackerId = "124"
    Subject = "Save File To Disk"
    Description = "Save File To Disk"

    def __init__(self, isPhaseCritical, fileContents, filePath = None):
        AbstractPhaseClass.__init__(self, isPhaseCritical)
        logging.info('Executing SaveFileToDisk phase...')
        self.FileContents = fileContents
        self.SetFilePath(filePath)

    @staticmethod
    def GetTempFilepath():
        temporaryDirectory = PathUtils.GetTempDirectory()
        temporaryFilename = PathUtils.GetTempFileRemovedWhenClosed("downloaded_temp_file_", ".exe")
        return join(temporaryDirectory, temporaryFilename)

    def SetFilePath(self, filePath):
        if StringUtils.IsEmptyOrNull(filePath):
            self.FilePath = self.GetTempFilepath()
        else:
            self.FilePath = PathUtils.ExpandPath(filePath)
            if path.isdir(self.FilePath):
                temporaryFilename = PathUtils.GetTempFileRemovedWhenClosed("downloaded_temp_file_", ".exe")
                self.FilePath = path.join(self.FilePath, temporaryFilename)

    def Setup(self):
        if FileUtils.FileExists(self.FilePath):
            self.PhaseReporter.Error('{0} already exist'.format(self.FilePath))
            return False
        return True

    def SaveFile(self):
        self.PhaseReporter.Info('Saving file to {0}'.format(self.FilePath))
        FileUtils.WriteToFile(self.FilePath, self.FileContents)
        if FileUtils.GetFilesize(self.FilePath) <= 0:
            logging.info("Could not save file to disk")
            return False
        return True

    def Cleanup(self):
        if FileUtils.DeleteFile(self.FilePath):
            self.PhaseReporter.Info("Downloaded file correctly removed")
        else:
            self.PhaseReporter.Error('Failed to remove downloaded file. You might want to manually remove it. {0}'.format(self.FilePath))
        return True

    def Run(self):
        phaseSuccessful = self.SaveFile()
        if phaseSuccessful:
            self.PhaseResult['temp_file_saved_to'] = self.FilePath
            self.PhaseReporter.Info('Successfully saved to {0}'.format(self.FilePath))
        else:
            self.PhaseReporter.Info('Failed to save file to {0}'.format(self.FilePath))
        return phaseSuccessful
