from ai_utils.phases.cryptolocker_dga import CryptolockerDGAPhaseClass
import unittest
from ai_utils.ai_logging.simplelogger import AiLoggerClass
import logging


class TestCryptolockerDGA(unittest.TestCase):

  @classmethod
  def setUpClass(cls):
    AiLoggerClass(loggingLevel=logging.DEBUG).Enable()

  def test_generate_domain_name(self):
    phase = CryptolockerDGAPhaseClass(True)
    domain_name = phase.generate_domain_name(1, 1, 2017)
    self.assertEqual(domain_name, 'acnlxxtaiildmku')

  def test_generate_domain_names(self):
    phase = CryptolockerDGAPhaseClass(True)
    domains = phase.generate_domain_names()
    self.assertEqual(len(domains), phase.MAX_DOMAIN_NAME_TRYCOUNT)

  def test_generate_full_domain_name(self):
    phase = CryptolockerDGAPhaseClass(True)
    phase.day, phase.month, phase.year = 1, 1, 2017
    tldr = ["com", "net", "biz", "ru", "org", "co.uk", "info"]
    for i in range(7):
      domain = phase.generate_domain_name(1, 1, 2017 + i)
      full_domain = phase.generate_full_domain_name(i)
      self.assertEqual(full_domain, domain + '.' + tldr[i])

  def test_resolve_domain_valid(self):
    phase = CryptolockerDGAPhaseClass(True)
    domain_info = phase.resolve_domain('google.com', 0)
    self.assertEqual(domain_info[1], 'google.com')
    self.assertEqual(domain_info[0], 0)

  def test_resolve_domain_invalid(self):
    phase = CryptolockerDGAPhaseClass(True)
    domain_info = phase.resolve_domain('google.com1', 0)
    self.assertEqual(domain_info, ())

  def test_run(self):
    phase = CryptolockerDGAPhaseClass(True)
    phase.MAX_DOMAIN_NAME_TRYCOUNT = 5
    phase.Execute()
    # just test no unexpected exception is thrown