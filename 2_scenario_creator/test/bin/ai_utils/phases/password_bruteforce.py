import logging
try:
  # noinspection PyUnresolvedReferences
  import aipythonlib
except:
  logging.error('error import aipythonlib')
import re
from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.scenarios.globals import FileUtils, StringUtils, PathUtils

class PasswordBruteforcePhaseClass(AbstractPhaseClass):
  TrackerId = "223"
  Subject = "Password Brute-Force"
  Description = "Password Brute-Force"

  def __init__(self, isPhaseCritical, targetMachine, serviceToCrack, commaSeparatedListOfUsernames, commaSeparatedListPasswords, userNamesFilepath, passwordsFilepath):
    AbstractPhaseClass.__init__(self, isPhaseCritical)
    self.TargetMachine = targetMachine
    self.ServiceToCrack = serviceToCrack
    self.CommaSeparatedListOfUsernames = commaSeparatedListOfUsernames
    self.CommaSeparatedListOfPasswords = commaSeparatedListPasswords
    self.UserNamesFilepath = userNamesFilepath
    self.PasswordsFilepath = passwordsFilepath
    self.UsernameOut = None
    self.PasswordOut = None

  def Setup(self):
    if StringUtils.IsEmptyOrNull(self.TargetMachine):
      self.PhaseReporter.Error("Target machine must be specified")
      return False
    if not self.ServiceToCrack:
      self.PhaseReporter.Error("Service to crack must be specified")
      return False
    if not PathUtils.FindFile("ncrack.exe"):
      self.PhaseReporter.Error("ncrack.exe not found in path")
      return False
    return True

  def ExtractUserinfo(self, stdOut):
    match = re.search('<<<<(.+?)>>>>', stdOut)
    if match:
      userInfo = match.group(1)
      userInfoParts = userInfo.split('====')
      if len(userInfoParts) == 2:
        self.UsernameOut = userInfoParts[0]
        self.PasswordOut = userInfoParts[1]
        return True
    return False

  def CrackWithProvidedUserInfo(self):
    if StringUtils.IsEmptyOrNull(self.CommaSeparatedListOfUsernames):
      logging.error("CommaSeparatedListOfUsernames:{0} empty".format(self.CommaSeparatedListOfUsernames))
      return False
    if StringUtils.IsEmptyOrNull(self.CommaSeparatedListOfPasswords):
      logging.error("CommaSeparatedListOfPasswords:{0} empty".format(self.CommaSeparatedListOfPasswords))
      return False
    #http://nmap.org/ncrack/man.html
    ncrackCommand = " -vvv --user {0} --pass {1} {2}:{3},CL=1,cr=2 -f".format(self.CommaSeparatedListOfUsernames,
      self.CommaSeparatedListOfPasswords, self.TargetMachine, self.ServiceToCrack)
    errorCode, exitCode, stdOut, stdError = aipythonlib.AiRunCommand("ncrack.exe", ncrackCommand, 30 * 60 * 1000)
    if 'Discovered credentials' in stdOut:
      return self.ExtractUserinfo(stdOut)
    else:
      return False

  def CrackWithDatabase(self):
    if StringUtils.IsEmptyOrNull(self.UserNamesFilepath):
      logging.error("UserNamesFilepath:{0} empty".format(self.UserNamesFilepath))
      return False
    if not FileUtils.FileExists(self.UserNamesFilepath):
      logging.error("User name file path {0} not found".format(self.UserNamesFilepath))
      return False
    if StringUtils.IsEmptyOrNull(self.PasswordsFilepath):
      logging.error("PasswordsFilepath:{0} empty".format(self.PasswordsFilepath))
      return False
    if not FileUtils.FileExists(self.PasswordsFilepath):
      logging.error("Password file path {0} not found".format(self.PasswordsFilepath))
      return False
    #http://nmap.org/ncrack/man.html
    ncrackCommand = " -vvv -U \"{0}\" -P \"{1}\" {2}:{3},CL=1,cr=2 -f".format(self.UserNamesFilepath,
      self.PasswordsFilepath, self.TargetMachine, self.ServiceToCrack)
    errorCode, exitCode, stdOut, stdError = aipythonlib.AiRunCommand("ncrack.exe", ncrackCommand, 30 * 60 * 1000)
    if 'Discovered credentials' in stdOut:
      return self.ExtractUserinfo(stdOut)
    else:
      return False

  def CrackPassword(self):
    if self.CrackWithProvidedUserInfo():
      return True
    else:
      return self.CrackWithDatabase()

  def Run(self):
    phaseSuccessful = self.CrackPassword()
    if phaseSuccessful:
      self.PhaseResult['password_found_for_user'] = self.UsernameOut
      self.PhaseReporter.Info('Credentials found for username: {0}'.format(self.UsernameOut))
      self.PhaseReporter.Info('Successfully cracked password')
    else:
      self.PhaseReporter.Info('Failed to crack password')
    return phaseSuccessful