from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.scenarios.globals import FileUtils
import logging
import os

class PersistenceThroughStartupFolderPhaseClass(AbstractPhaseClass):
    """This phase mimics malware that achieves persistence by adding files to the operating system startup directory.
    Specifically if this phase does not receive any parameter it will check which startup directory exist in the asset
    and then it will copy the C:\Windows\notepad.exe binary to all the existent startup directories with the
    'AttackIQPersistenceThroughStartupFolderBinary.exe' name.
    On the other hand, it can receive the startup folders that will be used, the source file that will be copied to those
    folders and the destination file name. This phase can run with none or all three parameters specified.

    Kwargs:
         isPhaseCritical (bool):  If the phase is critical.
         startupFolders (list):  A list of startup folder in which the files will be copied. This directories will be
                                 checked for its existence. Optional parameter.
         sourceFilePath (str):  The full path to the file that will be copied to the existing startup folders.
                                Optional parameter. e.g. c:\windows\notepad.exe
         destFileName (str):  The name that will be used to copy the file in the startup folders. Optional parameter.
                                e.g. notepad_copy.exe

      Returns:
         bool.  True if phase has been successful, False otherwise.
    """
    TrackerId = "821"
    Subject = "Persistence Through Startup Folder"
    Description = "This phase will copy some files to the startup folder in order to mimic this persistence technique"

    # https://msdn.microsoft.com/en-us/library/windows/desktop/dd378457
    STARTUP_FOLDERS = [
      # FOLDERID_CommonStartup/CSIDL_COMMON_STARTUP/CSIDL_COMMON_ALTSTARTUP default path
      '%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\StartUp',
      # FOLDERID_CommonStartup/CSIDL_COMMON_STARTUP/CSIDL_COMMON_ALTSTARTUP legacy path
      '%ALLUSERSPROFILE%\Start Menu\Programs\StartUp',
      # FOLDERID_Startup/CSIDL_STARTUP/CSIDL_ALTSTARTUP default path
      '%APPDATA%\Microsoft\Windows\Start Menu\Programs\StartUp',
      # FOLDERID_Startup/CSIDL_STARTUP/CSIDL_ALTSTARTUP legacy path
      '%USERPROFILE%\Start Menu\Programs\StartUp'
    ]

    def __init__(self, isPhaseCritical, startupFolders=None, sourceFilePath='', destFileName=''):
        logging.info(Messages.INFO11)
        AbstractPhaseClass.__init__(self, isPhaseCritical)
        self.StartupFolders = self._ProcessStartupFolders(startupFolders)
        self.SourceFile = self._SetupSourceFile(sourceFilePath)
        self.DestFileName = self._SetupDestFileName(destFileName)
        self.SuccessfulCopyPaths = []

    def Setup(self):
        if not self.StartupFolders:
            self.PhaseReporter.Error(Messages.ERROR1.format(self.STARTUP_FOLDERS))
            return False
        if not self.SourceFile:
            self.PhaseReporter.Error(Messages.ERROR2.format(self.SourceFile))
            return False
        if not FileUtils.FileExists(self.SourceFile):
            self.PhaseReporter.Error(Messages.ERROR3.format(self.SourceFile))
            return False
        if not self.DestFileName:
            self.PhaseReporter.Error(Messages.ERROR4.format(self.DestFileName))
            return False
        return True

    def Run(self):
        phaseSuccessful = self._CopyFilesToStartupFolders() > 0
        self._LogPhaseSuccess(phaseSuccessful)
        return phaseSuccessful

    def Cleanup(self):
        if self.SuccessfulCopyPaths:
            self.PhaseReporter.Info(Messages.INFO10.format(self.SuccessfulCopyPaths))
            for startupFile in self.SuccessfulCopyPaths:
                FileUtils.DeleteFile(startupFile)

    def _CopyFilesToStartupFolders(self):
        self.PhaseReporter.Info(Messages.INFO4)
        successNum = 0
        for startupFolder in self.StartupFolders:
            if self._CopyFileToStartupFolder(startupFolder):
                successNum += 1
        return successNum

    def _CopyFileToStartupFolder(self, startupFolder):
        destFilename = os.path.join(startupFolder, self.DestFileName)
        self.PhaseReporter.Info(Messages.INFO5.format(self.SourceFile, destFilename))
        if FileUtils.FileExists(destFilename):
            self.PhaseReporter.Warn(Messages.WARN1)
            return False
        return self._CopyFile(self.SourceFile, destFilename)

    def _CopyFile(self, source, dest):
        if FileUtils.CopyFile(source, dest):
            self.SuccessfulCopyPaths.append(dest)
            self.PhaseReporter.Info(Messages.INFO6)
            success = True
        else:
            self.PhaseReporter.Info(Messages.INFO7)
            success = False
        return success

    def _ProcessStartupFolders(self, startupFolders):
        param = []
        lookupStartupFolders = startupFolders or self.STARTUP_FOLDERS
        for startupFolder in lookupStartupFolders:
            expandedFolder = os.path.expandvars(startupFolder)
            if FileUtils.DirExists(expandedFolder):
                param.append(expandedFolder)
        self.PhaseReporter.Info(Messages.INFO1.format(param))
        return param

    def _SetupSourceFile(self, sourceFile):
        param = os.path.expandvars(sourceFile) if sourceFile else os.path.expandvars(r'%SYSTEMROOT%\notepad.exe')
        self.PhaseReporter.Info(Messages.INFO2.format(param))
        return param

    def _SetupDestFileName(self, destFileName):
        param = destFileName or 'AttackIQPersistenceThroughStartupFolderBinary.exe'
        self.PhaseReporter.Info(Messages.INFO3.format(param))
        return param

    def _LogPhaseSuccess(self, phaseSuccessful):
        if phaseSuccessful:
            self.PhaseResult['StartupFiles'] = self.SuccessfulCopyPaths
            self.PhaseReporter.Info(Messages.INFO8)
        else:
            self.PhaseReporter.Info(Messages.INFO9)

class Messages(object):
    INFO1 = 'File will be copied to the following existing startup folders: {0}'
    INFO2 = 'Binary ({0}) will be copied to startup folder/s'
    INFO3 = 'Name of the file copied to the startup folder/s: {0}'
    INFO4 = 'Copying files to startup folder/s...'
    INFO5 = 'Copying {0} to {1}'
    INFO6 = 'File successfully copied to startup folder'
    INFO7 = 'Failed to copy file to startup folder'
    INFO8 = 'Files could be created in startup folder in order to achieve persistence'
    INFO9 = 'Failed to copy files to startup folder in order to achieve persistence'
    INFO10 = 'Deleting files created in startup folder/s: {0}'
    INFO11 = 'Executing Persistence Through Startup Folder phase...'

    WARN1 = 'Destination file already exists. File will not be copied to avoid overwriting the original one.'

    ERROR1 = 'No startup folder ({0}) exist in the asset. Startup folder required.'
    ERROR2 = 'Source file parameter could not be set. This parameter is required.'
    ERROR3 = 'Source file does not exist. This file should exist in order to be copied to the startup folder.'
    ERROR4 = 'Destination file name parameter could not be set. This parameter is required'
