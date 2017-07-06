import os
import re
import ctypes
from tempfile import NamedTemporaryFile
from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.scenarios.globals import FileUtils, PathUtils
import logging

class RecordMicrophonePhaseClass(AbstractPhaseClass):
  TrackerId = "363"
  Subject = "Record Microphone Sounds"
  Description = "Record microphone sounds and stores it in a file"

  def __init__(self, isPhaseCritical, destFile='', recordDuration='00:10'):
    AbstractPhaseClass.__init__(self, isPhaseCritical)
    logging.info('Executing Record Microphone phase...')
    assert isinstance(recordDuration, type('')) or isinstance(recordDuration, type(u''))
    recordDuration = str(recordDuration)
    if destFile:
      assert isinstance(destFile, type('')) or isinstance(destFile, type(u''))
      destFile = str(destFile)
      self.DestFile = destFile + '.wma'
    else:
      namedTempFile = NamedTemporaryFile(delete=False, suffix='.wma')  # file is not deleted once file stream is closed
      self.DestFile = namedTempFile.name
      namedTempFile.close()
    self.RecordDuration = '0000:' + recordDuration

  def Setup(self):
    # A valid path will only accept upper and lower case letters, numbers, :, \, _ and spaces
    isvalidDestFile = True if re.match(r'[ :\\.\w-]+$', self.DestFile) else False
    isvalidRecordDuration = True if re.match('\d\d\d\d:\d\d:\d\d', self.RecordDuration) else False
    return isvalidDestFile and isvalidRecordDuration

  def ManualCleanup(self):
    success = FileUtils.DeleteFile(self.DestFile)
    if not success:
      self.PhaseReporter.Warn('File could not be deleted: {0}'.format(self.DestFile))
    return success

  def _FindCmdBinary(self, envVarSupport=False):
    if FileUtils.FileExists('C:\\Windows\\system32\\cmd.exe'):
      return 'C:\\Windows\\system32\\cmd.exe'
    elif FileUtils.FileExists('C:\\Windows\\SysWOW64\\cmd.exe'):
      return 'C:\\Windows\\SysWOW64\\cmd.exe'
    else:
      if envVarSupport:
        return os.path.expandvars("%COMSPEC%")
    return ''

  def _FindSoundRecorderBinary(self, envVarSupport=False):
    if FileUtils.FileExists('C:\\Windows\\System32\\SoundRecorder.exe'):
      return 'C:\\Windows\\System32\\SoundRecorder.exe'
    else:
      if envVarSupport:
        if FileUtils.FileExists(os.path.expandvars("%SystemRoot%") + '\\System32\\SoundRecorder.exe'):
          return os.path.expandvars("%SystemRoot%") + '\\System32\\SoundRecorder.exe'
    return ''

  def _ExecuteSoundRecorderBinary(self):
    self.PhaseReporter.Info('Recording sound from machine\'s microphone...')
    success = False
    cmdBinary = self._FindCmdBinary()
    soundRecorderBinary = self._FindSoundRecorderBinary(False)
    if cmdBinary:
      if FileUtils.FileExists(soundRecorderBinary):
        args = ['/C' , soundRecorderBinary,  '/FILE', self.DestFile, '/DURATION', self.RecordDuration]
        success = FileUtils.ExecuteFile(cmdBinary, arguments=args, wait=True)
      else:
        self.PhaseReporter.Info("SoundRecorder application could not be found in {0}.".format(soundRecorderBinary))
    else:
      self.PhaseReporter.Info("System shell could not be found.")
    return success

  def _CheckFile(self):
    self.PhaseReporter.Info('Checking if audio has been correctly stored in file...')
    return FileUtils.FileExists(self.DestFile) and FileUtils.GetFilesize(self.DestFile) > 0

  def _CheckInputDevices(self):
    self.PhaseReporter.Info('Searching microphone devices for recording sound...')
    # https://msdn.microsoft.com/en-us/library/ms713732(v=vs.85).aspx
    return ctypes.WinDLL("winmm.dll").waveInGetNumDevs() != 0

  def Run(self):
    phaseSuccessful = False
    if self._CheckInputDevices():
      if self._ExecuteSoundRecorderBinary():
        phaseSuccessful = self._CheckFile()
    else:
      self.PhaseReporter.Info('Input device could not be found')

    if phaseSuccessful:
      self.PhaseReporter.Info('Successfully recorded from microphone and output stored in {0}'.format(self.DestFile))
      self.PhaseReporter.Report('Audio from microphone\'s asset was recorded using the SoundRecorder Windows tool')
    else:
      self.PhaseReporter.Info('Failed to record from microphone')
    return phaseSuccessful
