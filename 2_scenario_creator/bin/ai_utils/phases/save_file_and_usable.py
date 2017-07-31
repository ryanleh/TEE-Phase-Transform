import logging
import random
import string
from os import path
from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.scenarios.globals import FileUtils, PathUtils
import binascii


class SaveFileAndUsablePhaseClass(AbstractPhaseClass):
    TrackerId = "02c50274-0873-4161-a7e0-cfdbf2e6a4f9"
    Subject = "Save File To Disk And Check if Usable"
    Description = "This phase saves a file and copies it within the same directory"

    def __init__(self, isPhaseCritical, fileContents, filePath, sha256Hash='', cleanup=True):
        AbstractPhaseClass.__init__(self, isPhaseCritical)
        logging.info('Executing SaveFileAndUsable phase...')
        self.FileContents = self._SetupFileContents(fileContents)
        self.FilePath = self._SetupFilePathParameter(filePath)
        self.SecondFilePath = self._SetupSecondFilePathParameter(filePath)
        self.SHA256Hash = self._SetupSHA256HashParameter(sha256Hash)
        self.CleanupParam = self._SetupCleanupParameter(cleanup)

    def Setup(self):
        if not self.FilePath:
            self.PhaseReporter.Error('File Path parameter is empty. Phase will fail.')
            return False
        if FileUtils.FileExists(self.FilePath):
            self.PhaseReporter.Error('File Path parameter ({0}) already exist. Phase will fail.'.format(self.FilePath))
            return False
        if not self.SecondFilePath:
            self.PhaseReporter.Error('The path to where the file should be copied could not be built. Phase will fail.')
            return False
        if FileUtils.FileExists(self.SecondFilePath):
            self.PhaseReporter.Error('Path to wehere the file would be copied ({0}) already exist. Phase will fail.'.format(self.SecondFilePath))
            return False
        if not self.FileContents:
            self.PhaseReporter.Error('Data to be saved to the filesystem is empty. Phase will fail.')
            return False
        return True

    def Run(self):
        if self.SHA256Hash:
            phaseSuccessful = self._SaveFile() and self._CopyFile() and self._CheckSHA256Hash()
        else:
            phaseSuccessful = self._SaveFile() and self._CopyFile()
        self._LogResult(phaseSuccessful)
        return phaseSuccessful

    def Cleanup(self):
        if self.CleanupParam:
            if self.FilePath and FileUtils.FileExists(self.FilePath):
                if FileUtils.DeleteFile(self.FilePath):
                    self.PhaseReporter.Info("Downloaded file correctly removed")
                else:
                    self.PhaseReporter.Error('Failed to remove downloaded file. You might want to manually remove it. Path: {0}'.format(self.FilePath))
            if self.SecondFilePath and FileUtils.FileExists(self.SecondFilePath):
                if FileUtils.DeleteFile(self.SecondFilePath):
                    self.PhaseReporter.Info("Copied file correctly removed")
                else:
                    self.PhaseReporter.Error('Failed to remove downloaded file. You might want to manually remove it. Path: {0}'.format(self.SecondFilePath))
        return True

    ###
    # Private Methods
    #################

    def _SaveFile(self):
        success = True
        self.PhaseReporter.Info('Saving data to {0}'.format(self.FilePath))
        saveSuccess = FileUtils.WriteToFile(self.FilePath, self.FileContents)
        if saveSuccess and FileUtils.GetFilesize(self.FilePath) > 0:
            self.PhaseReporter.Info('Data successfully saved to the filesystem')
        else:
            self.PhaseReporter.Info("Data could not be saved to the filesystem")
            success = False
        return success

    def _CopyFile(self):
        self.PhaseReporter.Info('Copying file {0} to {1}'.format(self.FilePath, self.SecondFilePath))
        success = FileUtils.CopyFile(self.FilePath, self.SecondFilePath)
        if success:
            self.PhaseReporter.Info('File successfully copied')
        else:
            self.PhaseReporter.Info("File could not be copied")
        return success

    def _CheckSHA256Hash(self):
        return self._CompareHashes(FileUtils.SHA256ForFile(self.FilePath), self.SHA256Hash) and self._CompareHashes(FileUtils.SHA256ForFile(self.SecondFilePath), self.SHA256Hash, True)

    def _CompareHashes(self, hash1, hash2, copiedFile=False):
        downloadedOrCopiedString = 'copied' if copiedFile else 'downloaded'
        if hash1 == hash2:
            success = True
            self.PhaseReporter.Info('SHA256 hash parameter matches the hash of the {} file'.format(downloadedOrCopiedString))
        else:
            success = False
            self.PhaseReporter.Info('SHA256 hash parameter does not match the hash of the {} file. Phase will fail'.format(downloadedOrCopiedString))
        return success

    def _LogResult(self, phaseSuccessful):
        if phaseSuccessful:
            self.PhaseResult['downloaded_file_to'] = self.FilePath
            self.PhaseResult['copied_file_to'] = self.SecondFilePath
            self.PhaseReporter.Info('Data successfully saved to filesystem and copied')
            msg = 'A file stored in memory was saved to the filesystem and copied to a different location.'
            msg = msg + ' File SHA256 hash: {}'.format(self.SHA256Hash) if self.SHA256Hash else msg
            self.PhaseReporter.Report(msg)
            if self.SHA256Hash:
                self.PhaseReporter.Mitigation('Add file with the following hash to your security technologies (e.g. Antivirus) blacklist: {}'.format(self.SHA256Hash))
        else:
            self.PhaseReporter.Info('Failed to save data and copy it data')

    def _SetupFilePathParameter(self, filePath):
        param = ''
        if filePath:
            filePath = PathUtils.ExpandPath(filePath)
            filePath = self._CreateRandomFileNameForPath(filePath, 'ai_downloaded_temp_file') if self._IsDir(filePath) else None
            param = filePath
        self.PhaseReporter.Info('File Path parameter: {0}'.format(param))
        return param

    def _SetupSecondFilePathParameter(self, filePath):
        param = ''
        if filePath:
            filePath = PathUtils.ExpandPath(filePath)
            filePath = self._CreateRandomFileNameForPath(filePath, 'ai_copied_temp_file') if self._IsDir(filePath) else None
            param = filePath
        self.PhaseReporter.Info('Second File Path parameter: {0}'.format(param))
        return param

    def _SetupFileContents(self, fileContents):
        param = ''
        if fileContents:
            param = fileContents
            self.PhaseReporter.Info('File Contents parameter: {0} (...)'.format(self._GetFileContents(fileContents, 10)))
        else:
            self.PhaseReporter.Info('Empty File Contents parameter: ')
        return param

    def _SetupSHA256HashParameter(self, md5Hash):
        param = ''
        if md5Hash:
            param = md5Hash
        self.PhaseReporter.Info('SHA256 Hash parameter: {0}'.format(param))
        return param

    def _SetupCleanupParameter(self, cleanup):
        param = ''
        if cleanup:
            param = cleanup
        self.PhaseReporter.Info('Cleanup parameter: {0}'.format(param))
        return param

    def _GetFileContents(self, fileContents, length):
        try:
            res = binascii.hexlify(fileContents[:length])
        except:
            res = ''
            pass
        return res

    def _IsDir(self, filePath):
        success = True
        if not path.isdir(filePath):
            self.PhaseReporter.Error('File Path ({0}) is not a valid directory. Phase will fail'.format(filePath))
            success = False
        return success

    def _CreateRandomFileNameForPath(self, filePath, name):
        randomString = self._CreateRandomString()
        temporaryFilename = ('{0}_{1}.exe'.format(name, randomString))
        return path.join(filePath, temporaryFilename)

    def _CreateRandomString(self):
        randomString = ''.join(random.choice(string.ascii_letters + string.digits) for _ in xrange(8))
        return randomString
