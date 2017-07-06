from ai_utils.utils.offensive.windows_passwords.windows_passwords_factory import WindowsPasswordsFactory
from ai_utils.phases.abstract_phase import AbstractPhaseClass
import logging

try:
  import aipythonlib
except Exception as e:
  logging.error('Error importing aipythonlib: {0}'.format(e))


class GetWindowsPasswordsPhaseClass(AbstractPhaseClass):
  TrackerId = "510"
  Subject = "Get Windows passwords"
  Description = "Get Windows passwords"

  def __init__(self, is_phase_critical, pwd_dumping_tool, cred_types=None, usernames=None):
    """
    This phase will execute Mimikatz in order to obtain the credentials cached in memory.

    :param is_phase_critical (bool): Boolean variable that identifies if this phase outcome affects the scenario
    outcome

    :param pwd_dumping_tool (str): The tool to be used to dump windows passwords.
    Valid options: mimikatz, undetectable_mimikatz

    :param cred_types (list): This parameter is a list that specifies what type of credentials will be printed in
    FireDrill UI. Only valid value: "all", "ntlm", "cleartext".

    This parameter will be used only for the following password dumping tools:
     - mimikatz: Valid options: "all", "ntlm", "cleartext"
     - undetectable_mimikatz: Valid options: "all", "ntlm", "cleartext"

    :param usernames (list): This parameter is a list that specifies what users will be the ones for which their
    credentials will be printed in the FireDrill UI.
    """
    AbstractPhaseClass.__init__(self, is_phase_critical)
    logging.debug('Executing GetWindowsPasswordsPhaseClass constructor')
    self.credentials_object = []
    self.valid_cred_types = ["all", "ntlm", "cleartext"]
    self.valid_pwd_dumping_tool = ['mimikatz', 'undetectable_mimikatz']
    self.pwd_dumping_tool = self.setup_pwd_dumping_tool(pwd_dumping_tool)
    self.cred_types = self.setup_cred_types_parameter(cred_types)
    self.usernames = self.setup_usernames_parameter(usernames)

  def Run(self):
    logging.debug('Executing Run')
    factory = WindowsPasswordsFactory(self.pwd_dumping_tool, self.cred_types, self.usernames, self.PhaseReporter)
    agent = factory.create_agent()
    phase_successful = agent.get_windows_passwords()
    self.credentials_object = agent.credentials_object  # scenarios such as pth retrieve this object directly
    return phase_successful

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

  def setup_pwd_dumping_tool(self, pwd_dumping_tool):
    logging.debug('Executing setup_pwd_dumping_tool. setup_pwd_dumping_tool: {}'.format(pwd_dumping_tool))
    if pwd_dumping_tool in self.valid_pwd_dumping_tool:
      param = pwd_dumping_tool
    else:
      logging.warning('Credential Theft tool "{}" is not valid. Valid options: "{}". Falling back to Original Mimikatz'.format(pwd_dumping_tool, ', '.join(self.valid_pwd_dumping_tool)))
      param = 'mimikatz'
    return param