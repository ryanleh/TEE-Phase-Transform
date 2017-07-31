from ai_utils.phases.save_file_and_usable import SaveFileAndUsablePhaseClass
from ai_utils.ai_logging.simplelogger import AiLoggerClass
from ai_utils.scenarios.globals import PathUtils
import unittest
import logging


class TestSaveFileAndUsablePhaseClass(unittest.TestCase):

    def setUp(self):
        AiLoggerClass(loggingLevel=logging.DEBUG).Enable()

    def test_run_correct_parameters(self):
        file_path = PathUtils.GetTempDirectory()
        file_contents = 'a'
        sfaupc = SaveFileAndUsablePhaseClass(True, file_contents, file_path)
        security_check_passed = sfaupc.Execute()
        self.assertTrue(security_check_passed, 'Test failed with File Contents: {0}, File Path: {1}'.format(file_contents, file_path))

    def test_run_empty_file_contents(self):
        file_path = PathUtils.GetTempDirectory()
        file_contents = None
        sfaupc = SaveFileAndUsablePhaseClass(True, file_contents, file_path)
        security_check_passed = sfaupc.Execute()
        self.assertFalse(security_check_passed, 'Test failed with File Contents: {0}, File Path: {1}'.format(file_contents, file_path))

    def test_run_empty_file_path(self):
        file_path = ''
        file_contents = 'a'
        sfaupc = SaveFileAndUsablePhaseClass(True, file_contents, file_path)
        security_check_passed = sfaupc.Execute()
        self.assertFalse(security_check_passed, 'Test failed with File Contents: {0}, File Path: {1}'.format(file_contents, file_path))

    def test_run_invalid_file_path(self):
        file_path = 'ThisPathDoesNotExist'
        file_contents = 'a'
        sfaupc = SaveFileAndUsablePhaseClass(True, file_contents, file_path)
        security_check_passed = sfaupc.Execute()
        self.assertFalse(security_check_passed, 'Test failed with File Contents: {0}, File Path: {1}'.format(file_contents, file_path))
