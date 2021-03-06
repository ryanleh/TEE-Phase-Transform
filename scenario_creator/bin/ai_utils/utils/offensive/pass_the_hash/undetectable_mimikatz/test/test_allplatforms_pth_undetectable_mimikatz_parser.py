from ai_utils.utils.offensive.pass_the_hash.undetectable_mimikatz.undetectable_mimikatz_parser import UndetectableMimikatzParser
from ai_utils.ai_logging.simplelogger import AiLoggerClass
from ai_utils.scenarios.globals import FileUtils, PathUtils
import unittest
import logging


class TestPTHUndetectableMimikatzParser(unittest.TestCase):

    def setUp(self):
        AiLoggerClass(loggingLevel=logging.DEBUG).Enable()
        self.valid_output_path = self._create_valid_file()
        self.valid_success_pattern = 'Pass the Hash Successful'
        self.invalid_output_path = 'invalidpath'
        self.invalid_success_pattern = 'Past the Hash Successful'
        self.empty_file = self._create_empty_file()
    
    def test_parse_pth_output_valid(self):
        parser = UndetectableMimikatzParser(self.valid_output_path, self.valid_success_pattern)
        success, err = parser.parse_pth_output()
        self.assertEqual(err, '')
        self.assertTrue(success)
    
    def test_parse_pth_output_invalid_pattern(self):
        parser = UndetectableMimikatzParser(self.valid_output_path, self.invalid_success_pattern)
        success, err = parser.parse_pth_output()
        good_error1 = err.startswith('Test Success Pattern')
        good_error2 = err.endswith('could not be found in the pass the hash command output file. Remote command executed using pass the hash has failed')
        self.assertTrue(good_error1)
        self.assertTrue(good_error2)
        self.assertFalse(success)
    
    def test_parse_pth_output_invalid_path(self):
        parser = UndetectableMimikatzParser(self.invalid_output_path, self.invalid_success_pattern)
        success, err = parser.parse_pth_output()
        self.assertEqual(err, 'Remote command output file has not been created. This means that the command executed passing the hash has failed')
        self.assertFalse(success)
    
    def test_parse_pth_output_empty_file(self):
        parser = UndetectableMimikatzParser(self.empty_file, self.valid_success_pattern)
        success, err = parser.parse_pth_output()
        self.assertEqual(err, 'Output file generated by command is empty. This means that the remote command was not successful')
        self.assertFalse(success)
    
    def tearDown(self):
        FileUtils.DeleteFile(self.valid_output_path)
        FileUtils.DeleteFile(self.empty_file)
    
    def _create_valid_file(self):
        path = PathUtils.GetTempFile('ai_test_', '.txt')
        FileUtils.WriteToFile(path, 'Pass the Hash Successful')
        return path
    
    def _create_empty_file(self):
        path = PathUtils.GetTempFile('ai_test_', '.txt')
        FileUtils.WriteToFile(path, '')
        return path
