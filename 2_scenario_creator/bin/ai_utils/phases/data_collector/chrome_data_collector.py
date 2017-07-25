from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.utils.filecollector import FileCollectorClass
from ai_utils.utils.zipfiles import FileZipperClass

class ChromeDataCollectorPhaseClass(AbstractPhaseClass):
  TrackerId = "168"
  Subject = "Collect Chrome Data"
  Description = "Collect Chrome Data"

  def __init__(self, isPhaseCritical, zipFileOutputPath):
    AbstractPhaseClass.__init__(self, isPhaseCritical)
    self.ZipFileOutputPath = zipFileOutputPath

  def Setup(self):
    listOfFolders = ["c:\\users\\*\\AppData\\Local\\Google\\Chrome\\", "c:\\Documents and Settings\\*\\Local Settings\\Application Data\\Google\\Chrome\\"]
    listOfPatterns = ['Login Data']
    self.FileCollector = FileCollectorClass(listOfFolders, listOfPatterns, 1)
    return True

  def CollectAndZipFiles(self):
    if not self.FileCollector.Collect():
      return False
    self.PhaseResult['chrome_files_collected'] =  str(self.FileCollector.ListOfFiles)
    fileZipper = FileZipperClass(self.ZipFileOutputPath, self.FileCollector.ListOfFiles)
    return fileZipper.Zip()

  def Run(self):
    phaseSuccessful = self.CollectAndZipFiles()
    if phaseSuccessful:
      self.PhaseReporter.Warn('Successfully collected Chrome data')
    else:
      self.PhaseReporter.Info('Failed to collect Chrome data')
    return phaseSuccessful