from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.utils.filecollector import FileCollectorClass
from ai_utils.utils.zipfiles import FileZipperClass

class FirefoxDataCollectorPhaseClass(AbstractPhaseClass):
  TrackerId = "173"
  Subject = "Collect Firefox Data"
  Description = "Collect Firefox Data"

  def __init__(self, isPhaseCritical, zipFileOutputPath):
    AbstractPhaseClass.__init__(self, isPhaseCritical)
    self.ZipFileOutputPath = zipFileOutputPath

  def Setup(self):
    listOfFolders = ["C:\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\", "C:\\Documents and Settings\\*\\Application Data\\Mozilla\\Firefox\\Profiles\\"]
    listOfPatterns = ['key*.db']
    self.FileCollector = FileCollectorClass(listOfFolders, listOfPatterns, 1)
    return True

  def CollectAndZipFiles(self):
    if not self.FileCollector.Collect():
      return False
    self.PhaseResult['firefox_files_collected'] = str(self.FileCollector.ListOfFiles)
    fileZipper = FileZipperClass(self.ZipFileOutputPath, self.FileCollector.ListOfFiles)
    return fileZipper.Zip()

  def Run(self):
    phaseSuccessful = self.CollectAndZipFiles()
    if phaseSuccessful:
      self.PhaseReporter.Warn('Successfully collected Firefox data')
    else:
      self.PhaseReporter.Info('Failed to collect Firefox data')
    return phaseSuccessful