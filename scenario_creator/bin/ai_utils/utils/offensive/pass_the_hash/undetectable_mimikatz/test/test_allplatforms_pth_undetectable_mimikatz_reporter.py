from ai_utils.utils.offensive.pass_the_hash.undetectable_mimikatz.undetectable_mimikatz_reporter import UndetectableMimikatzReporter
import unittest


class TestPTHMimikatzReporter(unittest.TestCase):

  def test_mimikatz_reporter_phase_successful(self):
    reporter = UndetectableMimikatzReporter('user', 'domaincontroller@attackiq.local', 'attackiq.local', None)
    reporter.report(True)

  def test_mimikatz_reporter_phase_failure(self):
    reporter = UndetectableMimikatzReporter('user', 'domaincontroller@attackiq.local', 'attackiq.local', None)
    reporter.report(False)

  def test_mimikatz_reporter_phase_failure_with_invalid_fqdn(self):
    reporter = UndetectableMimikatzReporter('user', 'domaincontroller@attackiq.local', '', None)
    reporter.report(False)

  def test_mimikatz_reporter_phase_failure_with_invalid_target(self):
    reporter = UndetectableMimikatzReporter('user', '', 'attackiq.local', None)
    reporter.report(False)
