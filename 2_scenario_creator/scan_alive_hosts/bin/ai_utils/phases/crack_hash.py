from ai_utils.phases.abstract_phase import AbstractPhaseClass
import logging


class CrackHashPhaseClass(AbstractPhaseClass):
  TrackerId = "PHS-85aaaabc-5c32-11e7-bd17-000c29c2ba76"
  Subject = "Crack Hash"
  Description = "Crack md5 hash"

  def __init__(self, isPhaseCritical, hash):
    AbstractPhaseClass.__init__(self, isPhaseCritical)
    self.hash = hash

  def Setup(self):
    return True

  def Run(self):
    phaseSuccess = False
    try:
      from Hash_Cracker import hashCracking
      self.PhaseReporter.Info('Successful import!')
    except ImportError as e:
      self.PhaseReporter.Info('Import failed: {}'.format(e))

    h = hashCracking()
    password = h.hashCrackWordlist(self.hash, "md5", "Wordlist.txt", True)
    if password:
      self.password = password
      self.PhaseReporter.Info('Password is: {}'.format(password))
      phaseSuccess = True
    else:
      self.password = None
      self.PhaseReporter.Info('Password could not be found')

    return phaseSuccess

  def Cleanup(self):
    cleanupSuccess = True
    return cleanupSuccess


