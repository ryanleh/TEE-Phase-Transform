import logging
from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.scenarios.globals import FileUtils, PathUtils
try:
  import aipythonlib
except Exception:
  print "Unable to import aipythonlib, phase will fail"
import re


class GetDomainControllerInfoPhaseClass(AbstractPhaseClass):
  TrackerId = "PHS-0d977930-41f2-11e5-9b7b-707781bc5c74"
  Subject = "getDomainControllerInfo"
  Description = "This phase collects the information of the Domain Controller for the local machine or user."

  def __init__(self, isPhaseCritical, deleteOutputFile=False):
    AbstractPhaseClass.__init__(self, isPhaseCritical)
    self.DomainName = ''
    self.InfoFileName = ''
    self.DeleteFile = deleteOutputFile

  def Run(self):
    self.PhaseReporter.Info("Getting Domain Controller Information.")
    phaseSuccessful = self._GetDomainControllerInfo()
    self.PhaseReporter.Report('Domain Controller information was retrieved by executing "nltest" Windows tool.')
    return phaseSuccessful

  def Cleanup(self):
    if self.DeleteFile:
      success = FileUtils.DeleteFile(self.InfoFileName)
      if not success:
        self.PhaseReporter.Warn(Messages.WARN1.format(self.InfoFileName))
    return

  ###
  # Internal Methods
  ######

  def _GetDomainControllerInfo(self):
    success = False
    if self._ExtractDomainName():
      shellCommand = '/c nltest /dsgetdc:"{0}"'.format(self.DomainName)
      timeout = 3000
      try:
        errorCode, exitCode, stdOut, stdErr = aipythonlib.AiRunCommand('cmd', shellCommand, timeout)
        self.DomainControllerInfo = stdOut.strip()
        logging.info(Messages.INFO4.format(self.DomainControllerInfo))
        if self.DomainControllerInfo:
          self.PhaseReporter.Info(Messages.INFO7)
          success = self._CreateInfoFile()
        else:
          self.PhaseReporter.Info(Messages.ERROR5)
      except Exception:
        logging.info(Messages.ERROR2)
        self.PhaseReporter.Info(Messages.ERROR5)
    return success

  def _ExtractDomainName(self):
    logging.info(Messages.INFO1)
    command = '/c systeminfo | findstr /B /C:"Domain"'
    timeout = 30000
    success = False
    try:
      errorCode, exitCode, stdOut, stdErr = aipythonlib.AiRunCommand('cmd', command, timeout)
      self.DomainName = self._ParseDomainNameString(stdOut)
      logging.info(Messages.INFO3.format(self.DomainName))
      self.PhaseReporter.Info(Messages.INFO6.format(self.DomainName))
      success = True
    except Exception:
      self.PhaseReporter.Info(Messages.ERROR4)
    return success

  def _ParseDomainNameString(self, stdOut):
    domainName = re.search(r'\s+.*', stdOut).group(0)
    domainName = domainName.strip() if domainName else ''
    return domainName

  def _CreateInfoFile(self):
    logging.info(Messages.INFO5)
    success = False
    domainControllerFile = PathUtils.GetTempFile(prefixArg='ai-dc-', suffixArg='.txt')
    if domainControllerFile and FileUtils.WriteToFile(domainControllerFile, self.DomainControllerInfo):
      self.InfoFileName = domainControllerFile
      success = True
      logging.info(Messages.INFO2.format(domainControllerFile))
    else:
      self.PhaseReporter.Error(Messages.ERROR3)
    return success


class Messages(object):
  INFO1 = 'Getting Domain Name from Machine'
  INFO2 = 'Successful in creating file from Domain Controller Info: {0}'
  INFO3 = 'Domain name is: {0}'
  INFO4 = 'Domain Controller Info is {0}'
  INFO5 = 'Writing Domain Controller Information to text file'
  INFO6 = 'Extracted Domain Name: {0}'
  INFO7 = 'Domain Controller Info Extracted'

  WARN1 = 'File could not be deleted: {0} Consider deleting manually.'

  ERROR1 = 'Unable to get domain name. Phase will fail.'
  ERROR2 = 'Unable to get domain controller information. Phase will fail'
  ERROR3 = 'Unable to create info file from Domain Controller Info. '
  ERROR4 = 'Failed to extract domain name'
  ERROR5 = 'Failed to extract domain controller info'
