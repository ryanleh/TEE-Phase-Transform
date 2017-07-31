from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.scenarios.globals import NetworkUtils
from cStringIO import StringIO
import hashlib
import logging

peLibSupported = False

try:
    import pefile
    peLibSupported = True
except:
    logging.exception('please install pefile package for this phase to work')


class DownloadFilePhaseClass(AbstractPhaseClass):
    TrackerId = "123"
    Subject = "Download File"
    Description = "Download File"

    def __init__(self, isPhaseCritical, url, checkIfExecutable, maxFileSize=0, fromConsole=False, sha256Hash=''):
        AbstractPhaseClass.__init__(self, isPhaseCritical)
        logging.info('Executing DownloadFile phase...')
        self.Url = self.SetupURLParameter(url)
        self.CheckIfExecutable = self.SetupCheckIfExecutableParameter(checkIfExecutable)
        self.MaxFileSize = self.SetupMaxFileSizeParameter(maxFileSize)
        self.FromConsole = self.SetupFromConsoleParameter(fromConsole)
        self.SHA256Hash = self.SetupSHA256Parameter(sha256Hash)

    def Setup(self):
        if not NetworkUtils.ValidateUrl(self.Url):
            self.PhaseReporter.Error('URL is not a valid. Phase will fail'.format(self.Url))
            return False
        if self.CheckIfExecutable is None:
            self.PhaseReporter.Info('Check If Executable parameter is not set. Phase proceed without checking if file is executable')
            self.CheckIfExecutable = False
        if not peLibSupported:
            self.PhaseReporter.Warn('File type check feature not available in the asset operating system. This check will be ignored')
            self.CheckIfExecutable = False
        return True

    def Run(self):
        if self.SHA256Hash:
            phaseSuccessful = self.DownloadAndCheckFile() and self.CompareHashes(self.SHA256FromMemory(), self.SHA256Hash)
        else:
            phaseSuccessful = self.DownloadAndCheckFile()
        self.LogResults(phaseSuccessful)
        return phaseSuccessful

    def DownloadAndCheckFile(self):
        success = True
        self.PhaseReporter.Info('Downloading file from {0}'.format(self.Url))
        downloadSuccess, response = self.DownloadFile()
        if downloadSuccess:
            if self.CheckResponseHTTPHeaders(response):
                self.ResponseOutput = self.GetMaxBytesFromResponse(response)
                success = self.DownloadedStreamIsExecutable() if self.CheckIfExecutable else True
        return success

    def DownloadFile(self):
        if self.FromConsole:
            success, response = NetworkUtils.DownloadFileFromConsole(self.Url)
        else:
            success, response = NetworkUtils.DownloadFile(self.Url)
        return success, response

    def CheckResponseHTTPHeaders(self, response):
        success = True
        if response.headers.get('content-type') == 'text/html':
            logging.info("HTML file downloaded from {0}".format(self.Url))
            success = False
        if response.headers.get('content-length') == 0:
            logging.info("Content-length is 0")
            success = False
        return success

    def GetMaxBytesFromResponse(self, response):
        fileString = StringIO()
        for responseBlock in response.iter_content(1024):
            if not responseBlock:
                break
            fileString.write(responseBlock)
            if 0 < self.MaxFileSize <= fileString.tell():
                break
        return fileString.getvalue()

    def DownloadedStreamIsExecutable(self):
        success = False
        self.PhaseReporter.Info('Checking if downloaded file is executable...')
        if self.IsExecutable():
            success = True
            self.PhaseReporter.Info('Downloaded file is detected as an executable/dll')
        else:
            self.PhaseReporter.Info('Downloaded file is not detected as an executable/dll')
        return success

    def IsExecutable(self):
        success = False
        try:
            pe = pefile.PE(data=self.ResponseOutput, fast_load=True)
            success = pe.is_exe() or pe.is_dll()
        except NameError:
            self.PhaseReporter.Warn('File type check feature not available in the asset operating system. Executable check will fail and phase will fail.')
        except pefile.PEFormatError:
            logging.info('Downloaded file is not detected as an executable')
        return success

    def SHA256FromMemory(self):
        try:
            hash = hashlib.sha256()
            hash.update(self.ResponseOutput)
            return hash.hexdigest()
        except Exception as e:
            logging.error('Something went wrong while computing SHA256 hash. Error: {0}'.format(e))
        return None

    def CompareHashes(self, hash1, hash2):
        if hash1 == hash2:
            success = True
            self.PhaseReporter.Info('SHA256 hash parameter matches the hash of the downloaded file')
        else:
            success = False
            self.PhaseReporter.Info('SHA256 hash parameter does not match the hash of the downloaded file. Phase will fail')
        return success

    def LogResults(self, phaseSuccessful):
        self.PhaseResult['url_to_download_from'] = self.Url
        if phaseSuccessful:
            self.PhaseReporter.Info('Successfully downloaded file from {0}'.format(self.Url))
            msg = 'A file with the following SHA256 hash was downloaded and stored in memory: {}'.format(self.SHA256Hash) if self.SHA256Hash else 'A file was downloaded and stored in memory.'
            self.PhaseReporter.Report(msg)
            if self.SHA256Hash:
                self.PhaseReporter.Mitigation('Your network security controls should block file transmissions with the following SHA256 hash: {}'.format(self.SHA256Hash))
        else:
            self.PhaseReporter.Info('Failed to download file from {0}'.format(self.Url))

    def SetupURLParameter(self, url):
        param = ''
        if url:
            param = NetworkUtils.CheckUrlPrefix(url)
        self.PhaseReporter.Info('URL parameter: {0}'.format(param))
        return param

    def SetupCheckIfExecutableParameter(self, checkIfExecutable):
        param = None
        if checkIfExecutable:
            param = checkIfExecutable
        self.PhaseReporter.Info('Check If Executable parameter: {0}'.format(param))
        return param

    def SetupMaxFileSizeParameter(self, maxFileSize):
        param = 0
        if maxFileSize:
            param = maxFileSize
        self.PhaseReporter.Info('Max File Size parameter: {0}'.format(param))
        return param

    def SetupFromConsoleParameter(self, fromConsole):
        param = False
        if fromConsole:
            param = fromConsole
        self.PhaseReporter.Info('From Console parameter: {0}'.format(param))
        return param

    def SetupSHA256Parameter(self, sha256Hash):
        param = ''
        if sha256Hash:
            param = sha256Hash
        self.PhaseReporter.Info('SHA256 Hash parameter: {0}'.format(param))
        return param
