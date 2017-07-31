from ai_utils.phases.get_windows_passwords import GetWindowsPasswordsPhaseClass
from ai_utils.ai_logging.simplelogger import AiLoggerClass
import unittest


# All meaningful tests are located inside the windows_passwords utility directory. It can be found:
# ai_utils.utils.offensive.windows_passwords

class TestGetWindowsPasswordsPhaseClass(unittest.TestCase):

    def setUp(self):
        AiLoggerClass().Enable()
    
    def test_phase(self):
        phase = GetWindowsPasswordsPhaseClass(True, 'mimikatz')
        success = phase.Execute()
        self.assertTrue(success)
