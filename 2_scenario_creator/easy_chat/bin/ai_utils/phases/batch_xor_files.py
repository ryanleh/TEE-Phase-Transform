import os
import logging
from ai_utils.encryption.xor import XorEncryptionClass
from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.scenarios.globals import FileUtils, PathUtils, StringUtils

class BatchXorFilesPhaseClass(AbstractPhaseClass):
  TrackerId = "218"
  Subject = "File Obfuscation(Xor) in Batch"
  Description = "File Obfuscation(Xor) in Batch"
  EncryptionKey = r'Attack of the clones'

  def __init__(self, isPhaseCritical, outputFolderPath, listOfFilesToXor):
    AbstractPhaseClass.__init__(self, isPhaseCritical)
    assert isinstance(listOfFilesToXor, list)
    self.OutputFolderPath = outputFolderPath
    self.ListOfFilesToXor = listOfFilesToXor
    self.ListOfFilesAfterXorOut = []
    self.XorEncryptor = XorEncryptionClass(self.EncryptionKey)

  def XorBuffer(self, inputBuffer):
    return self.XorEncryptor.Encrypt(inputBuffer)

  def XorFile(self, inputFilePath, outputFilePath):
    if not os.path.isfile(inputFilePath):
      logging.info("{0} is not a file".format(inputFilePath))
      return False
    inputContents = FileUtils.ReadFromFile(inputFilePath)
    if StringUtils.IsEmptyOrNull(inputContents):
      logging.info("{0} is null of empty".format(inputFilePath))
      return False
    encryptedBuffer = self.XorBuffer(inputContents)
    return FileUtils.WriteToFile(outputFilePath, encryptedBuffer)

  def GetPathForFileAfterXor(self, inputFilePath):
    return PathUtils.GetOutputFilePath(self.OutputFolderPath, inputFilePath)

  def XorFiles(self):
    for fileToXor in self.ListOfFilesToXor:
      outputFilePath = self.GetPathForFileAfterXor(fileToXor)
      if outputFilePath:
        successful = self.XorFile(fileToXor, outputFilePath)
        if successful:
          self.ListOfFilesAfterXorOut.append(outputFilePath)
    return len(self.ListOfFilesAfterXorOut) > 0

  def ManualCleanup(self):
    FileUtils.DeleteFolder(self.OutputFolderPath, safetyOn=False)
    return True

  def Run(self):
    phaseSuccessful = self.XorFiles()
    if phaseSuccessful:
      self.PhaseResult['list_of_files_after_xor'] = str(self.ListOfFilesAfterXorOut)
      self.PhaseReporter.Info('Successfully Obfuscated(Xor) {0} files in batch'.format(len(self.ListOfFilesAfterXorOut)))
    else:
      self.PhaseReporter.Info('Failed to Obfuscate(Xor) files in batch')
    return phaseSuccessful
