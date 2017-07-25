from ai_utils.phases.custom_http_request import CustomHTTPRequestPhaseClass
from ai_utils.ai_logging.simplelogger import AiLoggerClass
from copy import deepcopy
import unittest
import logging


class TestCustomHTTPRequest(unittest.TestCase):

  def setUp(self):
    AiLoggerClass(loggingLevel=logging.DEBUG).Enable()
    self.phase_params_status_code = {
      "data_type": "no_data",
      "data": "",
      "data_is_base64_encoded": False,
      "validation_method": "server_response_code",
      "match_outcome": "pass",
      "if_host_is_unreachable_match_outcome": "fail",
      "headers": [
        {}
      ],
      "server_response_code_value": 301,
      "url": "http://google.com",
      "method": "GET",
      "http_version": "HTTP/1.1"
    }
    self.phase_params_expression = {
      "data_type": "no_data",
      "data": "",
      "data_is_base64_encoded": False,
      "validation_method": "response_expressions",
      "match_outcome": "pass",
      "if_host_is_unreachable_match_outcome": "fail",
      "headers": [
        {}
      ],
      "post_variables": [
        {}
      ],
      "server_response_expressions": [
        {
          "value": "attackiq"
        }
      ],
      "url": "https://www.attackiq.com",
      "method": "GET",
      "http_version": "HTTP/1.1"
    }


  def test_valid_status_code(self):
    phase = CustomHTTPRequestPhaseClass(True, self.phase_params_status_code)
    success = phase.Execute()
    phase.Cleanup()
    self.assertTrue(success)

  def test_invalid_status_code(self):
    params = deepcopy(self.phase_params_status_code)
    params['server_response_code_value'] = 12345
    phase = CustomHTTPRequestPhaseClass(True, params)
    success = phase.Execute()
    phase.Cleanup()
    self.assertFalse(success)

  def test_valid_status_code_switch_logic(self):
    params = deepcopy(self.phase_params_status_code)
    params['match_outcome'] = 'fail'
    phase = CustomHTTPRequestPhaseClass(True, params)
    success = phase.Execute()
    phase.Cleanup()
    self.assertFalse(success)

  def test_invalid_status_code_switch_logic(self):
    params = deepcopy(self.phase_params_status_code)
    params['match_outcome'] = 'fail'
    params['server_response_code_value'] = 12345
    phase = CustomHTTPRequestPhaseClass(True, params)
    success = phase.Execute()
    phase.Cleanup()
    self.assertTrue(success)

  def test_valid_content(self):
    phase = CustomHTTPRequestPhaseClass(True, self.phase_params_expression)
    success = phase.Execute()
    phase.Cleanup()
    self.assertTrue(success)

  def test_invalid_content(self):
    params = deepcopy(self.phase_params_expression)
    params['server_response_expressions'][0]['value'] = 'thiscontentwillneverappearinattackiq.com'
    phase = CustomHTTPRequestPhaseClass(True, params)
    success = phase.Execute()
    phase.Cleanup()
    self.assertFalse(success)

  def test_valid_content_and_post_params(self):
    params = deepcopy(self.phase_params_expression)
    params["post_variables"] = [
      {
        "name": "varname",
        "value": "varvalue"
      }
    ]
    params['server_response_expressions'][0]['value'] = 'attackiq.com'
    phase = CustomHTTPRequestPhaseClass(True, params)
    success = phase.Execute()
    phase.Cleanup()
    self.assertTrue(success)

  def test_unreachable_server(self):
    params = deepcopy(self.phase_params_status_code)
    params['url'] = 'http://127.0.0.258'
    phase = CustomHTTPRequestPhaseClass(True, params)
    success = phase.Execute()
    phase.Cleanup()
    self.assertFalse(success)

  def test_unreachable_server_but_succeed(self):
    params = deepcopy(self.phase_params_status_code)
    params['url'] = 'http://127.0.0.258'
    params['if_host_is_unreachable_match_outcome'] = 'pass'
    phase = CustomHTTPRequestPhaseClass(True, params)
    success = phase.Execute()
    phase.Cleanup()
    self.assertTrue(success)


  def test_valid_content_with_data(self):
    params = deepcopy(self.phase_params_expression)
    params['data']= 'this is my text'
    params['data_is_base64_encoded'] = True
    phase = CustomHTTPRequestPhaseClass(True, params)
    success = phase.Execute()
    phase.Cleanup()
    self.assertTrue(success)
