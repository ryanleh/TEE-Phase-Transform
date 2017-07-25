from ai_utils.utils.collectionutils import CollectionUtilsClass as CollectionUtils
from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.scenarios.globals import NetworkUtils
from urlparse import urlparse
from binascii import hexlify
import httplib
import urllib2
import logging
import urllib
import base64
import socket
import re


class NoRedirectHandler(urllib2.HTTPRedirectHandler):

  def http_error_302(self, req, fp, code, msg, headers):
    logging.debug('Executing http_error_302. req: {}, fp: {}, code: {}, msg: {}, headers: {}'.format(req, fp, code, msg, headers))
    infourl = urllib.addinfourl(fp, headers, req.get_full_url())
    infourl.status = code
    infourl.code = code
    return infourl

  http_error_301 = http_error_303 = http_error_307 = http_error_302


class CustomHTTPRequestPhaseClass(AbstractPhaseClass):
  TrackerId = "402"
  Subject = "Send Custom HTTP Request"
  Description = "This scenario sends a fully customized HTTP request"

  VALID_DATA_TYPES = ['include_data', 'include_post_variables', 'no_data']
  VALID_VALIDATION_METHODS = ['server_response_code', 'response_expressions']
  VALID_MATCH_OUTCOMES = ['pass', 'fail']
  VALID_IF_HOST_IS_UNREACHABLE = ['pass', 'fail']

  def __init__(self, is_phase_critical, model):
    logging.debug('Executing __init__. isPhaseCritical: {}, model: {}'.format(is_phase_critical, model))
    AbstractPhaseClass.__init__(self, is_phase_critical)
    logging.info('Executing Custom HTTP Request phase...')
    self.method = self.setup_method_parameter(model.get('method'))
    self.url = self.setup_url_parameter(model.get('url'))
    self.http_version = self.setup_http_version_parameter(model.get('http_version'))
    self.headers = self.setup_headers_parameter(model.get('headers'))
    self.data_type = self.setup_data_type_parameter(model.get('data_type'))
    self.data = self.setup_data_parameter(model.get('post_variables'), model.get('data_is_base64_encoded'), model.get('data'))
    self.validation_method = model.get('validation_method')
    self.match_outcome = model.get('match_outcome')
    self.if_host_is_unreachable_match_outcome = model.get('if_host_is_unreachable_match_outcome')
    self.server_response_code_value = model.get('server_response_code_value')
    self.server_response_expressions = model.get('server_response_expressions')
    self._http_vsn = None
    self._http_vsn_str = None

  def Setup(self):
    logging.debug('Executing Setup')
    if not self.method:
      self.PhaseReporter.Error('Method parameter is empty. Phase will fail')
      return False
    if not self.url:
      self.PhaseReporter.Error('URL parameter is empty. Phase will fail')
      return False
    if not self.http_version:
      self.PhaseReporter.Error('HTTP Version parameter is empty. Phase will fail')
      return False
    if not self.data_type:
      self.PhaseReporter.Error('Data Type parameter is empty. Phase will fail')
      return False
    if self.data_type not in self.VALID_DATA_TYPES:
      self.PhaseReporter.Error('Unexpected Data Type parameter: {0}. Valid options: {1}. Phase will fail'.format(self.data_type, self.VALID_DATA_TYPES))
      return False
    if not self.validation_method:
      self.PhaseReporter.Error('Validation Method parameter is empty. Phase will fail')
      return False
    if self.validation_method not in self.VALID_VALIDATION_METHODS:
      self.PhaseReporter.Error('Unexpected Validation Method parameter: {0}. Valid options: {1}. Phase will fail'.format(self.validation_method, self.VALID_VALIDATION_METHODS))
      return False
    if self.match_outcome not in self.VALID_MATCH_OUTCOMES:
      self.PhaseReporter.Error('Unexpected Match Outcome parameter: {0}. Valid options: {1}. Phase will fail'.format(self.match_outcome, self.VALID_MATCH_OUTCOMES))
      return False
    if self.if_host_is_unreachable_match_outcome not in self.VALID_IF_HOST_IS_UNREACHABLE:
      self.PhaseReporter.Error('Unexpected If Host Is Unreachable Match Outcome parameter: {0}. Valid options: {1}. Phase will fail'.format(self.if_host_is_unreachable_match_outcome, self.VALID_IF_HOST_IS_UNREACHABLE))
      return False
    self.backup_library_modifications()
    return True

  def Run(self):
    logging.debug('Executing Run')
    connection, error_sending_request = self.send_request()
    phase_successful = self.set_outcome_if_destination_unreachable() if error_sending_request else self.validate_response(connection)
    self.log_results(phase_successful)
    return phase_successful

  def Cleanup(self):
    logging.debug('Executing Cleanup')
    return self.revert_library_modifications()
 
  def send_request(self):
    logging.debug('Executing send_request')
    error_sending_request = False
    connection = None
    try:
      connection = self.open_url_lib_connection()
      self.PhaseReporter.Info('Request sent to {}'.format(self.url))
    except socket.gaierror:
      self.PhaseReporter.Info('Unable to get IP address for {0}'.format(self.url))
      error_sending_request = True
    except httplib.BadStatusLine:
      self.PhaseReporter.Info('Could not retrieve response status code. Remote host might be down or response might be empty')
      error_sending_request = True
    except urllib2.URLError:
      self.PhaseReporter.Info('Unable to resolve domain. Check internet connection and DNS settings.')
      error_sending_request = True
    except Exception as e:
      self.PhaseReporter.Info('An unexpected error occurred sending the request. Error: {0}'.format(e))
      error_sending_request = True
    return connection, error_sending_request

  def open_url_lib_connection(self):
    logging.debug('Executing open_url_lib_connection')
    logging.info('Opening urllib connection...')
    opener, request = self.setup_request()
    try:
        connection = opener.open(request, timeout=10)
    except urllib2.HTTPError, e:
        connection = e
    return connection

  def setup_request(self):
    logging.debug('Executing setup_request')
    logging.info('Building urllib2 request and handler..')
    httplib.HTTPConnection._http_vsn = 10
    httplib.HTTPConnection._http_vsn_str = self.http_version
    method = self.method
    handler = NoRedirectHandler()
    opener = urllib2.build_opener(handler)
    request = urllib2.Request(self.url, self.data, self.headers)
    request.get_method = lambda: method  # overload the get method function with an anonymous function
    return opener, request

  def set_outcome_if_destination_unreachable(self):
    logging.debug('Executing set_outcome_if_destination_unreachable')
    logging.info('Host unreachable failed. If Host Is Unreachable Match Outcome parameter is "pass", phase will be successful')
    return self.if_host_is_unreachable_match_outcome == 'pass'

  def validate_response(self, connection):
    logging.debug('Executing validate_response. connection: {}'.format(connection))
    response_data, status_code = self.read_response_from_connection(connection)
    if self.validation_method == 'server_response_code':
      outcome = self.validate_using_server_response_code(status_code)
    elif self.validation_method == 'response_expressions':
      outcome = self.validate_using_response_expressions(response_data)
    else:
      self.PhaseReporter.Error('Invalid Validation Method parameter: {0}. Valid values: {1}'.format(self.validation_method, self.VALID_VALIDATION_METHODS))
      outcome = False
    return outcome

  def read_response_from_connection(self, connection):
    logging.debug('Executing read_response_from_connection. connection: {}'.format(connection))
    logging.info('Reading response data from urllib connection object...')
    status_code = connection.code
    response_data = connection.read()
    if response_data:
      self.PhaseReporter.Debug('Hexadecimal encoded response data: {0} (...)'.format(hexlify(response_data[:10])))
    else:
      self.PhaseReporter.Info('No response data could be read')
    return response_data, status_code

  def validate_using_server_response_code(self, status_code):
    logging.debug('Executing validate_using_server_response_code. status_code: {}'.format(status_code))
    if self.server_response_code_value == status_code:
      self.PhaseReporter.Info('Response status code matches the one provided in the parameters: {0}'.format(status_code))
      outcome = self.set_outcome_depending_on_match_outcome_parameter(True)
    else:
      self.PhaseReporter.Info('Response status code does not match the one provided in the parameters: {0}, Received {1}'.format(self.server_response_code_value, status_code))
      outcome = self.set_outcome_depending_on_match_outcome_parameter(False)
    return outcome

  def set_outcome_depending_on_match_outcome_parameter(self, is_expected_result_received):
    logging.debug('Executing set_outcome_depending_on_match_outcome_parameter. is_expected_result_received: {}'.format(is_expected_result_received))
    logging.info('Match Outcome parameter: {0}, Expected Result Received: {1}'.format(self.match_outcome, is_expected_result_received))
    if self.match_outcome == 'pass':
      outcome = is_expected_result_received
    elif self.match_outcome == 'fail':
      outcome = not is_expected_result_received
    else:
      self.PhaseReporter.Error('Invalid Match Outcome parameter: {0}. Valid values: {1}. Phase will fail'.format(self.match_outcome, self.VALID_MATCH_OUTCOMES))
      outcome = False
    logging.info('Computed outcome from the Match Outcome parameter and the Expected Result Received: {0}'.format(outcome))
    return outcome

  def validate_using_response_expressions(self, response_data):
    logging.debug('Executing validate_using_response_expressions. response_data (hex): {}'.format(hexlify(response_data)))
    if self.server_response_expressions:
      outcome = self.find_expressions_in_response(response_data)
    else:
      self.PhaseReporter.Error('Empty Response Expression parameter. Phase will fail')
      outcome = False
    return outcome

  def find_expressions_in_response(self, response_data):
    logging.debug('Executing find_expressions_in_response. response_data (hex): {}'.format(hexlify(response_data)))
    found = False
    for item in self.server_response_expressions:
      if self.find_expression_in_response(item, response_data):
        found = True
        break
    return self.set_outcome_depending_on_match_outcome_parameter(found)

  def find_expression_in_response(self, item, response_data):
    logging.debug('Executing find_expression_in_response. item: {}, response_data (hex): {}'.format(item, hexlify(response_data)))
    found = False
    try:
      value = item.get('value')
      if value:
        match = re.search(value, response_data)
        if match:
          self.PhaseReporter.Info('Valid expression "{}" found in server response'.format(value))
          found = True
    except Exception as e:
      logging.error('Something went wrong finding expression in the response. Error: {0}'.format(e))
    return found

  def log_results(self, phase_successful):
    logging.debug('Executing log_results. phase_successful: {}'.format(phase_successful))
    if phase_successful:
      local_ip = NetworkUtils.GetLocalIP()
      from_str = 'from "{}" '.format(local_ip) if local_ip else ''
      self.PhaseReporter.Info('The phase was successful given the parameters')
      self.PhaseReporter.Report('Connection {}to "{}" was successful given the phase parameters.'.format(from_str, self.url))
      self.PhaseReporter.Mitigation('Connections {}to "{}" should be either monitored or prevented'.format(from_str, self.url))
    else:
      self.PhaseReporter.Info('The phase failed given the parameters')

  ###
  # Setup Methods
  ###############

  @staticmethod
  def setup_method_parameter(method):
    logging.debug('Executing setup_method_parameter. method: {}'.format(method))
    param = ''
    if method:
      param = method
    return param

  @staticmethod
  def setup_url_parameter(url):
    logging.debug('Executing setup_url_parameter. url: {}'.format(url))
    param = ''
    if url:
      parsed = urlparse(url)
      param = url if parsed.scheme else 'http://' + url
    return param

  @staticmethod
  def setup_http_version_parameter(http_version):
    logging.debug('Executing setup_http_version_parameter. http_version: {}'.format(http_version))
    param = ''
    if http_version:
      param = http_version
    return param

  def setup_headers_parameter(self, headers):
    logging.debug('Executing setup_headers_parameter. headers: {}'.format(headers))
    param = {}
    if headers:
      param = CollectionUtils.NameValueArrayToDictionary(headers)
    return param

  def setup_data_type_parameter(self, data_type):
    logging.debug('Executing setup_data_type_parameter. data_type: {}'.format(data_type))
    param = ''
    if data_type:
      param = data_type
    return param

  def setup_data_parameter(self, post_variables, data_is_base64_encoded, data):
    logging.debug('Executing setup_data_parameter. post_variables: {}, data_is_base64_encoded: {}, data: {}'.format(post_variables, data_is_base64_encoded, data))
    try:
      param = self.get_data_from_form(post_variables, data_is_base64_encoded, data)
    except Exception as e:
      logging.error('Data parameter could not be processed. Error: {0}'.format(e))
      param = None
    return param

  def get_data_from_form(self, post_variables, data_is_base64_encoded, data):
    logging.debug('Executing get_data_from_form. post_variables: {}, data_is_base64_encoded: {}, data: {}'.format(post_variables, data_is_base64_encoded, data))
    if self.data_type == 'include_data':
      res = base64.b64decode(data) if data_is_base64_encoded else data
    elif self.data_type == 'include_post_variables':
      post_variables = CollectionUtils.NameValueArrayToDictionary(post_variables)
      res = urllib.urlencode(post_variables)
    elif self.data_type == 'no_data':
      res = None
    else:
      raise TypeError('Invalid data type parameter: {0}. Phase will fail'.format(self.data_type))
    return res

  def backup_library_modifications(self):
    logging.debug('Executing backup_library_modifications.')
    self._http_vsn = httplib.HTTPConnection._http_vsn
    self._http_vsn_str = httplib.HTTPConnection._http_vsn_str

  def revert_library_modifications(self):
    logging.debug('Executing revert_library_modifications.')
    if not self._http_vsn or not self._http_vsn_str:
      return True
    httplib.HTTPConnection._http_vsn = self._http_vsn
    httplib.HTTPConnection._http_vsn_str = self._http_vsn_str
    if httplib.HTTPConnection._http_vsn == self._http_vsn and httplib.HTTPConnection._http_vsn_str == self._http_vsn_str:
      return True
    return False
