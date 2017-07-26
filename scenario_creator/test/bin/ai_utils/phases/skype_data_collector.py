import os
from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.utils.filecollector import FileCollectorClass
from ai_utils.utils.zipfiles import FileZipperClass
from ai_utils.scenarios.globals import PathUtils

class SkypeDataCollectorPhaseClass(AbstractPhaseClass):
  TrackerId = "169"
  Subject = "Collect Skype Data"
  Description = "Collect Skype Data"

  def __init__(self, isPhaseCritical):
    AbstractPhaseClass.__init__(self, isPhaseCritical)

  def Setup(self):
    listOfFolders = ["c:\\users\\*\\AppData\\**\\Skype\\", "c:\\Documents and Settings\\*\\Local Settings\\Application Data\\**\\Skype\\"]
    listOfPatterns = ['main.db']
    self.FileCollector = FileCollectorClass(listOfFolders, listOfPatterns, 1)
    self.ZipFileOut = os.path.join(PathUtils.GetTempDirectory(), 'data.zip')
    return True

  def CollectAndZipFiles(self):
    if not self.FileCollector.Collect():
      return False
    self.PhaseResult['files_collected'] = str(self.FileCollector.ListOfFiles)
    fileZipper = FileZipperClass(self.ZipFileOut, self.FileCollector.ListOfFiles)
    return fileZipper.Zip()

  def Run(self):
    phaseSuccessful = self.CollectAndZipFiles()
    if phaseSuccessful:
      self.PhaseReporter.Info('Successfully collected Skype data')
    else:
      self.PhaseReporter.Info('Failed to collect Skype data')
    return phaseSuccessful