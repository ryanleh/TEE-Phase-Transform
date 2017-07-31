import os
from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.utils.filecollector import FileCollectorClass
from ai_utils.utils.zipfiles import FileZipperClass
from ai_utils.scenarios.globals import StringUtils, PathUtils

class FileSystemSearchAndCollectPhaseClass(AbstractPhaseClass):
    TrackerId = "170"
    Subject = "Search File System and Collect"
    Description = "Search File System and Collect"

    def __init__(self, isPhaseCritical, commaSeparatedListOfFolderPatterns, commaSeparatedListOfFilePatterns, maximumFileCount, maximumCumulativeSize):
        AbstractPhaseClass.__init__(self, isPhaseCritical)
        self.ListOfFolderPatterns = StringUtils.SplitAndTrim(commaSeparatedListOfFolderPatterns)
        self.ListOfFilePatterns = StringUtils.SplitAndTrim(commaSeparatedListOfFilePatterns)
        self.MaximumFileCount = maximumFileCount
        self.MaximumCumulativeSize = maximumCumulativeSize

    def Setup(self):
        self.FileCollector = FileCollectorClass(self.ListOfFolderPatterns, self.ListOfFilePatterns, self.MaximumFileCount, self.MaximumCumulativeSize)
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
            self.PhaseReporter.Info('Successfully collected {0} files'.format(len(self.FileCollector.ListOfFiles)))
            self.PhaseReporter.Info('Collected files: {0}'.format(self.FileCollector.ListOfFiles))
        else:
            self.PhaseReporter.Info('Failed to collect requested files')
        return phaseSuccessful
