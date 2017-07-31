from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.utils.filecollector import FileCollectorClass
from ai_utils.utils.zipfiles import FileZipperClass

class MicrosoftDataCollectorPhaseClass(AbstractPhaseClass):
    TrackerId = "174"
    Subject = "Collect IE Data"
    Description = "Collect IE Data"

    def __init__(self, isPhaseCritical, zipFileOutputPath):
        AbstractPhaseClass.__init__(self, isPhaseCritical)
        self.ZipFileOutputPath = zipFileOutputPath

    def Setup(self):
        listOfFolders = ["C:\\Users\\*\\AppData\\Local\\Microsoft\\Credentials\\"]
        listOfPatterns = ['*']
        self.FileCollector = FileCollectorClass(listOfFolders, listOfPatterns, 1)
        return True

    def CollectAndZipFiles(self):
        if not self.FileCollector.Collect():
            return False
        self.PhaseResult['microsoft_files_collected'] = str(self.FileCollector.ListOfFiles)
        fileZipper = FileZipperClass(self.ZipFileOutputPath, self.FileCollector.ListOfFiles)
        return fileZipper.Zip()

    def Run(self):
        phaseSuccessful = self.CollectAndZipFiles()
        if phaseSuccessful:
            self.PhaseReporter.Warn('Successfully collected Microsoft credentials')
        else:
            self.PhaseReporter.Info('Failed to collect Microsoft credentials')
        return phaseSuccessful
